//! Клавиши, до которых разметка не добирается.
//!
//! Slint узнаёт Ctrl+C/V/X/A по букве, которую отдала раскладка (в бэкенде это
//! `logical_key`), а на русской она «с», «м», «ч», «ф» — и копирование со
//! вставкой в полях ввода просто пропадают. Физическая клавиша при этом
//! известна: она от раскладки не зависит.
//!
//! PrtScn — та же история с другой стороны: приложение поднято с правами
//! администратора (их требует TUN), а UIPI прячет нажатия от процессов пониже,
//! и пока фокус у нашего окна, «Ножницы» о клавише не узнают. Значит, позвать
//! их нужно самим.
//!
//! Оба случая решаются до Slint: события winit проходят через этот обработчик
//! раньше, чем бэкенд переводит их в свои.

use i_slint_backend_winit::winit::event::{ElementState, KeyEvent, WindowEvent};
use i_slint_backend_winit::winit::event_loop::ActiveEventLoop;
use i_slint_backend_winit::winit::keyboard::{KeyCode, ModifiersState, PhysicalKey};
use i_slint_backend_winit::winit::window::{Window, WindowId};
use i_slint_backend_winit::{CustomApplicationHandler, EventResult};

#[derive(Default)]
pub struct Shortcuts {
    /// Модификаторы приходят своим событием — winit не кладёт их в нажатие.
    mods: ModifiersState,
    /// Окно на прошлом `Moved` торчало за пределы экранов. См. `repaint_all`.
    clipped: bool,
}

impl CustomApplicationHandler for Shortcuts {
    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        winit_window: Option<&Window>,
        slint_window: Option<&slint::Window>,
        event: &WindowEvent,
    ) -> EventResult {
        match event {
            // Окно ездит за край экрана и обратно: пока часть была за краем,
            // GDI её не рисовал, а Slint перерисовывает только изменившееся.
            // Пока окно хоть частично снаружи (и один раз при возвращении)
            // перерисовываем его целиком.
            WindowEvent::Moved(_) => {
                if let (Some(winit_window), Some(slint_window)) = (winit_window, slint_window) {
                    let clipped = sticks_out(winit_window);
                    if clipped || self.clipped {
                        repaint_all(slint_window);
                    }
                    self.clipped = clipped;
                }
                EventResult::Propagate
            }
            // Сон/блокировка/смена монитора: DWM мог выбросить поверхность окна,
            // а приложение об этом не узнаёт. Фокус — самый дешёвый повод
            // убедиться, что на экране не мусор.
            WindowEvent::Focused(true) => {
                if let Some(slint_window) = slint_window {
                    repaint_all(slint_window);
                }
                EventResult::Propagate
            }
            WindowEvent::ModifiersChanged(mods) => {
                self.mods = mods.state();
                EventResult::Propagate
            }
            // Синтетические нажатия приходят пачкой при возврате фокуса — это
            // не то, что нажал человек.
            WindowEvent::KeyboardInput { event, is_synthetic: false, .. } => {
                self.key(event, slint_window)
            }
            _ => EventResult::Propagate,
        }
    }
}

impl Shortcuts {
    fn key(&self, event: &KeyEvent, window: Option<&slint::Window>) -> EventResult {
        let PhysicalKey::Code(code) = event.physical_key else {
            return EventResult::Propagate;
        };

        if code == KeyCode::PrintScreen {
            // На отпускании: пока клавиша зажата, Windows шлёт повторы, а
            // оверлей нужен один.
            if event.state == ElementState::Released {
                crate::app::runtime().spawn(async {
                    let _ = crate::api::open_screen_snip().await;
                });
            }
            return EventResult::Propagate;
        }

        if !self.mods.control_key() {
            return EventResult::Propagate;
        }
        let Some(letter) = latin(code) else {
            return EventResult::Propagate;
        };
        let Some(window) = window else {
            return EventResult::Propagate;
        };

        // Своё событие вместо чужого: настоящее заменяется целиком, иначе
        // сочетание сработало бы дважды. Модификаторы Slint ведёт сам — Ctrl
        // до него дошёл своим чередом.
        let text = slint::SharedString::from(letter);
        window.dispatch_event(match event.state {
            ElementState::Pressed => slint::platform::WindowEvent::KeyPressed { text },
            ElementState::Released => slint::platform::WindowEvent::KeyReleased { text },
        });
        EventResult::PreventDefault
    }
}

/// Буква, которая стоит на этой клавише в латинской раскладке. Только те
/// сочетания, которые разбирает Slint: выделить всё, копировать, вставить,
/// вырезать, отменить и вернуть.
fn latin(code: KeyCode) -> Option<&'static str> {
    Some(match code {
        KeyCode::KeyA => "a",
        KeyCode::KeyC => "c",
        KeyCode::KeyV => "v",
        KeyCode::KeyX => "x",
        KeyCode::KeyY => "y",
        KeyCode::KeyZ => "z",
        _ => return None,
    })
}


/// Окно не целиком лежит на каком-либо мониторе (хотя бы один угол снаружи).
fn sticks_out(window: &Window) -> bool {
    let (Ok(pos), size) = (window.outer_position(), window.outer_size()) else {
        return false;
    };
    let monitors: Vec<_> = window
        .available_monitors()
        .map(|m| {
            let p = m.position();
            let s = m.size();
            (p.x, p.y, p.x + s.width as i32, p.y + s.height as i32)
        })
        .collect();
    if monitors.is_empty() {
        return false;
    }
    let (w, h) = (size.width as i32, size.height as i32);
    // Крайние пиксели: правый/нижний — последний внутри окна.
    let corners = [
        (pos.x, pos.y),
        (pos.x + w - 1, pos.y),
        (pos.x, pos.y + h - 1),
        (pos.x + w - 1, pos.y + h - 1),
    ];
    corners.iter().any(|&(x, y)| {
        !monitors.iter().any(|&(l, t, r, b)| x >= l && x < r && y >= t && y < b)
    })
}

/// Перерисовать окно целиком, а не только то, что изменилось.
///
/// Софтверный рендер Slint держит собственный буфер и отдаёт GDI только
/// «грязные» прямоугольники. Часть окна за краем экрана GDI отсекает — в
/// поверхности DWM там остаётся пусто, — и когда окно возвращают, это место
/// никто не перерисовывает: в буфере всё «уже нарисовано». Выглядит как
/// прозрачные куски интерфейса, которые оживают только по мере обновления.
fn repaint_all(window: &slint::Window) {
    use i_slint_core::lengths::{LogicalPoint, LogicalRect, LogicalSize};
    use i_slint_core::partial_renderer::DirtyRegion;
    use slint::private_unstable_api::re_exports::WindowInner;

    let size = window.size().to_logical(window.scale_factor());
    if size.width <= 0.0 || size.height <= 0.0 {
        return;
    }
    let all = LogicalRect::new(LogicalPoint::new(0.0, 0.0), LogicalSize::new(size.width, size.height));
    WindowInner::from_pub(window).window_adapter().renderer().mark_dirty_region(DirtyRegion::from(all));
    window.request_redraw();
}
