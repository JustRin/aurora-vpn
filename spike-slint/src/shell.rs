//! Оболочка приложения: значок в трее, единственный экземпляр и закрытие в
//! трей. Раньше всё это давали плагины Tauri.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

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
}

/// Пункты текущего меню. Не thread_local: смена языка пересобирает меню, и
/// сверять щелчок надо с тем набором, что висит в трее сейчас, а не с тем,
/// что был при установке значка.
static IDS: Mutex<Option<MenuIds>> = Mutex::new(None);

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
    // Показать окно по просьбе второго запуска — дорога, которой значок не
    // нужен: она работает и когда трей собрать не удалось.
    watch_show_flag(ui.as_weak());

    // Обработчики ставятся раньше меню и значка: muda с tray-icon запоминают
    // их в OnceLock, и первое же событие, пришедшее до установки, навсегда
    // закрепило бы «обработчика нет» — дальше события уходили бы в канал, из
    // которого никто не читает.
    //
    // Обработчик, а не опрос канала таймером: таймеры Slint живут в
    // событийном цикле, и любая его заминка — вложенный модальный цикл
    // Windows, затянувшийся кадр — молча съедала бы щелчки по меню. Windows
    // зовёт эти обработчики прямо из оконной процедуры значка, в потоке
    // интерфейса.
    {
        let weak = ui.as_weak();
        let handle = handle.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            dispatch(&event.id, &weak, &handle);
        }));
    }
    {
        let weak = ui.as_weak();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            // Левый клик по значку — то же, что «Показать окно».
            if let TrayIconEvent::Click {
                button: tray_icon::MouseButton::Left,
                button_state: tray_icon::MouseButtonState::Up,
                ..
            } = event
            {
                let _ = weak.upgrade_in_event_loop(|ui| show(&ui));
            }
        }));
    }

    let Some(icon) = icon() else { return };
    let tray = TrayIconBuilder::new()
        .with_tooltip("Aurora VPN")
        .with_menu(Box::new(build_menu()))
        .with_icon(icon)
        .build();
    let Ok(tray) = tray else { return };
    TRAY.with(|slot| *slot.borrow_mut() = Some(tray));
}

/// Сторож флажка второго запуска. Свой поток, а не таймер интерфейса: просьба
/// показать окно приходит редко, а зависеть она должна только от самого цикла,
/// который окно и покажет.
fn watch_show_flag(ui: slint::Weak<AppWindow>) {
    let Some(flag) = show_flag() else { return };
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(300));
        if flag.exists() {
            let _ = std::fs::remove_file(&flag);
            let _ = ui.upgrade_in_event_loop(|ui| show(&ui));
        }
    });
}

/// Пункты меню, разложенные по своим идентификаторам.
#[derive(Clone)]
struct MenuIds {
    show: MenuId,
    connect: MenuId,
    disconnect: MenuId,
    quit: MenuId,
}

/// Щелчок по пункту меню. Идентификаторы читаются заново на каждый щелчок:
/// смена языка пересобирает меню, а вместе с ним и их.
fn dispatch(id: &MenuId, ui: &slint::Weak<AppWindow>, handle: &AppHandle) {
    let ids = IDS.lock().ok().and_then(|ids| ids.clone());
    let Some(ids) = ids else { return };

    if *id == ids.show {
        let _ = ui.upgrade_in_event_loop(|ui| show(&ui));
    } else if *id == ids.connect {
        let handle = handle.clone();
        app::runtime().spawn(async move {
            let _ = api::connect(handle).await;
        });
    } else if *id == ids.disconnect {
        let handle = handle.clone();
        app::runtime().spawn(async move {
            let _ = api::disconnect(handle).await;
        });
    } else if *id == ids.quit {
        quit(handle);
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
    if let Ok(mut ids) = IDS.lock() {
        *ids = Some(MenuIds {
            show: show.id().clone(),
            connect: connect.id().clone(),
            disconnect: disconnect.id().clone(),
            quit: quit.id().clone(),
        });
    }

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

/// Единственная дорога наружу: снять значок, опустить туннель и уйти.
///
/// Не через `quit_event_loop()`: «Выход» обязан срабатывать всегда, а цикл
/// может быть занят своим — вложенным модальным циклом Windows, затянувшимся
/// кадром — или не дойти до конца уборки. Здесь всё решается вне его.
pub fn quit(handle: &AppHandle) {
    static QUITTING: AtomicBool = AtomicBool::new(false);
    // Крестик и меню трея подряд, сторож и уборка — заходов может быть
    // несколько, уход всё равно один.
    if QUITTING.swap(true, Ordering::SeqCst) {
        return;
    }

    // Значок исчезает из трея только вместе со своим процессом; ушедший
    // раньше оставляет призрака до первого наведения мыши. Из потока
    // интерфейса он снимается сразу, из чужого — просьбой к циклу.
    remove_tray();
    let _ = slint::invoke_from_event_loop(remove_tray);
    // Окно убирается сразу, не дожидаясь конца уборки: «Выход» должен
    // отзываться мгновенно.
    handle.with_ui(|ui| {
        ui.window()
            .with_winit_window(|window| window.set_visible(false));
    });

    // Уборка — в своём потоке: quit зовут и из интерфейса, и из задач tokio, а
    // block_on внутри рантайма — паника.
    {
        let handle = handle.clone();
        std::thread::spawn(move || {
            shutdown(&handle);
            std::process::exit(0);
        });
    }

    // Сторож на случай, если уборка где-то заклинит: ядро не отвечает, реестр
    // занят. Уйти без возврата прокси плохо, а остаться висеть мёртвым окном —
    // хуже: пользователь такое приложение уже не закроет.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(5));
        std::process::exit(0);
    });
}

fn remove_tray() {
    TRAY.with(|slot| drop(slot.borrow_mut().take()));
}

/// Закрытие окна: в трей или совсем — как настроено.
pub fn on_close(ui: &AppWindow, handle: &AppHandle) {
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
        quit(handle);
    }
}

/// Приложение уходит: опустить туннель и вернуть системный прокси на место.
/// Блокирующе и намеренно — после этого процесс завершится.
pub fn shutdown(handle: &AppHandle) {
    app::runtime().block_on(async {
        let _ = api::disconnect(handle.clone()).await;
    });
}
