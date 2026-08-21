//! Оболочка приложения: значок в трее, единственный экземпляр и закрытие в
//! трей. Раньше всё это давали плагины Tauri.

use std::cell::RefCell;
use std::path::PathBuf;

use i_slint_backend_winit::WinitWindowAccessor;
use slint::ComponentHandle;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::api;
use crate::app::{self, AppHandle};
use crate::AppWindow;

/// Сторона иконки в ресурсах: те же пиксели, что у иконки окна.
const ICON_SIDE: u32 = 128;

thread_local! {
    /// Значок держим живым столько же, сколько окно: с его падением он
    /// исчезает из трея.
    static TRAY: RefCell<Option<TrayIcon>> = const { RefCell::new(None) };
    static PUMP: RefCell<Option<slint::Timer>> = const { RefCell::new(None) };
}

// ------------------------------------------------------- единственный экземпляр

/// Файл-флажок: второй запуск оставляет его и уходит, работающий экземпляр
/// видит и показывает окно.
///
/// Не окно и не событие: приложение обычно поднято с правами администратора
/// (их требует TUN), а ярлык на рабочем столе запускает обычный процесс —
/// сообщения и объекты ядра между такими процессами Windows режет по уровню
/// целостности. Файл в своей папке настроек проходит везде.
fn show_flag() -> Option<PathBuf> {
    app::config_dir().ok().map(|dir| dir.join("show-window"))
}

/// Имя сторожа единственного экземпляра.
#[cfg(windows)]
const MUTEX_NAME: &str = "Local\\AuroraVPN.SingleInstance";

/// Аргумент, с которым приложение перезапускает само себя с правами
/// администратора. Обычный второй запуск его не несёт.
pub const RELAUNCH_FLAG: &str = "--relaunch";

/// Сколько ждать, пока уходящий процесс отпустит сторожа. Реально — около
/// секунды: столько занимает остановка ядра и возврат системного прокси.
const RELAUNCH_WAIT_MS: u32 = 15_000;

/// Работает ли уже другой экземпляр. Только проверка, без захвата: сторож
/// понадобится позже и другому процессу.
#[cfg(windows)]
fn another_instance_running() -> bool {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

    let name = HSTRING::from(MUTEX_NAME);
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, &name) } {
        Ok(handle) => {
            let _ = unsafe { CloseHandle(handle) };
            true
        }
        Err(_) => false,
    }
}

/// Передать запуск задаче планировщика, если она есть.
///
/// Включённый «запуск сразу с правами администратора» — это задача, которая
/// поднимает то же приложение с правами и без запроса UAC. Без такой передачи
/// обычный щелчок по ярлыку открывал неповышенный экземпляр, и первое, что
/// видел пользователь с включённой галочкой, — просьбу перезапуститься.
///
/// Возвращает true, когда эстафета передана: этому процессу пора уйти.
#[cfg(windows)]
pub fn hand_off_to_elevated_task() -> bool {
    if crate::sys::elevate::is_elevated() || another_instance_running() {
        return false;
    }
    crate::sys::autostart::start_elevated_task()
}

#[cfg(not(windows))]
pub fn hand_off_to_elevated_task() -> bool {
    false
}

/// Первый ли это экземпляр. Второй просит показать окно и завершается.
#[cfg(windows)]
pub fn claim_single_instance() -> bool {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

    // Мьютекс намеренно течёт: он должен жить всё время работы процесса, а
    // закрывать его при выходе незачем — система сделает это сама.
    let name = HSTRING::from(MUTEX_NAME);
    let Ok(handle) = (unsafe { CreateMutexW(None, true, &name) }) else {
        // Не смогли проверить — лучше запуститься, чем не запуститься.
        return true;
    };
    // Дескриптор не закрываем: сторож должен жить всё время работы процесса, а
    // на выходе система закроет его сама — и мьютекс станет «брошенным».
    let taken = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if !taken {
        return true;
    }

    // Перезапуск с правами: прежний процесс ещё жив, но уже уходит — UAC
    // отпускает нас раньше, чем тот успевает остановить ядро. Ждём, пока он
    // отпустит сторожа: на выходе процесса мьютекс становится «брошенным», и
    // ожидание завершается WAIT_ABANDONED. Без этого новый экземпляр видел
    // занятого сторожа, уходил — и приложение просто исчезало с экрана.
    if std::env::args().any(|arg| arg == RELAUNCH_FLAG) {
        // Истёкшее ожидание — не повод пропасть: прежний экземпляр уже получил
        // команду уйти, и если он завис, подняться и прибрать за ним лучше, чем
        // не подняться вовсе — осиротевшее ядро снимет kill_orphan на старте.
        let _ = unsafe { WaitForSingleObject(handle, RELAUNCH_WAIT_MS) };
        return true;
    }

    if let Some(flag) = show_flag() {
        let _ = std::fs::write(&flag, "");
    }
    // Право вынести окно на передний план у только что запущенного процесса
    // есть, у давно работающего — нет; передаём его.
    crate::sys::elevate::yield_foreground();
    false
}

#[cfg(not(windows))]
pub fn claim_single_instance() -> bool {
    true
}

// ------------------------------------------------------------------- трей

/// Собрать значок и подключить его события к окну.
pub fn install(ui: &AppWindow, handle: &AppHandle) {
    let Some(icon) = icon() else { return };
    let menu = build_menu();
    let ids = MenuIds::current();

    let tray = TrayIconBuilder::new()
        .with_tooltip("Aurora VPN")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build();
    let Ok(tray) = tray else { return };
    TRAY.with(|slot| *slot.borrow_mut() = Some(tray));

    // События трея приходят в свои каналы, а не в цикл Slint: забираем их
    // тем же таймером, что сторожит флажок второго запуска.
    let pump = slint::Timer::default();
    let weak = ui.as_weak();
    let handle = handle.clone();
    pump.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(250),
        move || {
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                let Some(ui) = weak.upgrade() else { return };
                ids.dispatch(&event.id, &ui, &handle);
            }
            while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                // Левый клик по значку — то же, что «Показать окно».
                if let TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                } = event
                {
                    if let Some(ui) = weak.upgrade() {
                        show(&ui);
                    }
                }
            }
            if let Some(flag) = show_flag() {
                if flag.exists() {
                    let _ = std::fs::remove_file(&flag);
                    if let Some(ui) = weak.upgrade() {
                        show(&ui);
                    }
                }
            }
        },
    );
    PUMP.with(|slot| *slot.borrow_mut() = Some(pump));
}

/// Пункты меню, разложенные по своим идентификаторам.
#[derive(Clone)]
struct MenuIds {
    show: MenuId,
    connect: MenuId,
    disconnect: MenuId,
    quit: MenuId,
}

thread_local! {
    static IDS: RefCell<Option<MenuIds>> = const { RefCell::new(None) };
}

impl MenuIds {
    fn current() -> Self {
        IDS.with(|ids| ids.borrow().clone().expect("меню трея собрано"))
    }

    fn dispatch(&self, id: &MenuId, ui: &AppWindow, handle: &AppHandle) {
        if *id == self.show {
            show(ui);
        } else if *id == self.connect {
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let _ = api::connect(handle).await;
            });
        } else if *id == self.disconnect {
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let _ = api::disconnect(handle).await;
            });
        } else if *id == self.quit {
            let _ = slint::quit_event_loop();
        }
    }
}

fn build_menu() -> Menu {
    let labels = crate::tr(|l| {
        [
            l.tray_show.clone(),
            l.tray_connect.clone(),
            l.tray_disconnect.clone(),
            l.tray_quit.clone(),
        ]
    });
    let show = MenuItem::new(&labels[0], true, None);
    let connect = MenuItem::new(&labels[1], true, None);
    let disconnect = MenuItem::new(&labels[2], true, None);
    let quit = MenuItem::new(&labels[3], true, None);
    IDS.with(|ids| {
        *ids.borrow_mut() = Some(MenuIds {
            show: show.id().clone(),
            connect: connect.id().clone(),
            disconnect: disconnect.id().clone(),
            quit: quit.id().clone(),
        })
    });

    let menu = Menu::new();
    let _ = menu.append_items(&[
        &show,
        &PredefinedMenuItem::separator(),
        &connect,
        &disconnect,
        &PredefinedMenuItem::separator(),
        &quit,
    ]);
    menu
}

/// Меню на другом языке. Значок пересобирать незачем — меняется только меню.
pub fn relabel() {
    TRAY.with(|slot| {
        if let Some(tray) = slot.borrow().as_ref() {
            tray.set_menu(Some(Box::new(build_menu())));
        }
    });
}

fn icon() -> Option<tray_icon::Icon> {
    const PIXELS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.rgba"));
    tray_icon::Icon::from_rgba(PIXELS.to_vec(), ICON_SIDE, ICON_SIDE).ok()
}

// ------------------------------------------------------------------- окно

/// Показать окно из трея.
pub fn show(ui: &AppWindow) {
    crate::sys::elevate::yield_foreground();
    let window = ui.window();
    window.set_minimized(false);
    window.with_winit_window(|w| {
        w.set_visible(true);
        w.focus_window();
    });

    // Пока окно спрятано, Windows очищает его буфер, а Slint об этом не знает:
    // сбрасывать кэш частичной перерисовки он умеет только по событию Occluded,
    // которого на Windows не бывает (renderer/sw.rs, occluded()). В итоге в
    // вернувшемся окне рисуется лишь то, что изменилось с прошлого кадра, —
    // и оно выглядит пустым. Пересборка амбиент-слоя помечает грязным всё
    // окно: слой растянут на него целиком, и кадр рисуется заново.
    crate::repaint_ambient(ui);
}

/// Закрытие окна: в трей или совсем — как настроено.
pub fn on_close(ui: &AppWindow) {
    let to_tray = TRAY.with(|slot| slot.borrow().is_some())
        && ui.global::<crate::Conf>().get_close_to_tray();
    if to_tray {
        // Прячем средствами winit, а не Window::hide(). Тот закрывает окно
        // Slint целиком: заново созданное поднималось пустым и прозрачным —
        // софтверный рендер считал, что перерисовывать в нём нечего. Здесь
        // окно остаётся живым, со своим содержимым и своим местом на экране,
        // и возвращается мгновенно.
        ui.window().with_winit_window(|window| window.set_visible(false));
    } else {
        let _ = slint::quit_event_loop();
    }
}

/// Приложение уходит: опустить туннель и вернуть системный прокси на место.
/// Блокирующе и намеренно — после этого процесс завершится.
pub fn shutdown(handle: &AppHandle) {
    app::runtime().block_on(async {
        let _ = api::disconnect(handle.clone()).await;
    });
}
