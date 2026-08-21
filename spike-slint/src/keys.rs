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
}

impl CustomApplicationHandler for Shortcuts {
    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _winit_window: Option<&Window>,
        slint_window: Option<&slint::Window>,
        event: &WindowEvent,
    ) -> EventResult {
        match event {
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
