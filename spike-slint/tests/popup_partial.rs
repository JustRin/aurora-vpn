//! Частичная перерисовка под открытым PopupWindow.
//!
//! Сценарий с «Обзора»: раскрыт выбор сервера, а под ним раз в секунду
//! обновляется график. Софтверный рендер перерисовывает только грязную область
//! подложки — и обязан поверх неё заново положить попап, иначе график
//! проступает сквозь меню.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter, WindowEvent};
use slint::Rgb8Pixel;

slint::slint! {
    // Точная копия GraphPath из theme.slint: вьюбокс привязан к размеру.
    component GraphPath inherits Path {
        width: 100%;
        height: 100%;
        viewbox-width: self.width / 1px;
        viewbox-height: self.height / 1px;
        stroke-width: 1.8px;
    }

    export component TestWin inherits Window {
        width: 400px;
        height: 300px;
        background: black;
        in property <int> tick;
        in property <string> line-commands;
        in property <string> area-commands;

        // Страница-скролл, как DashboardPage inherits ScrollArea.
        Flickable {
            VerticalLayout {
                padding: 8px;
                HorizontalLayout {
                    alignment: start;
                    // Выбор сервера: кнопка с попапом, вложенная в лэйауты.
                    picker := Rectangle {
                        width: 120px;
                        height: 24px;
                        background: #333333;
                        menu := PopupWindow {
                            close-policy: no-auto-close;
                            x: 0;
                            y: parent.height + 4px;
                            width: 200px;
                            height: 200px;
                            Rectangle {
                                background: #00ff00;
                                drop-shadow-blur: 50px;
                                drop-shadow-offset-y: 18px;
                                drop-shadow-color: #000000aa;
                                // Список внутри меню, как ScrollArea с узлами.
                                Flickable {
                                    VerticalLayout {
                                        for i in 4: Rectangle {
                                            height: 48px;
                                            background: #00ff00;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Rectangle { height: 40px; }
                // «График»: карточка, как hero на «Обзоре», — сетка, две
                // заливки и две линии, чьи commands приходят из Rust.
                Rectangle {
                    height: 90px;
                    background: #111122;
                    VerticalLayout {
                        Text {
                            height: 16px;
                            text: root.tick == 0 ? "пик 100 КБ/с" : "пик 342 КБ/с";
                            color: white;
                            font-size: 12px;
                        }
                        graph := Rectangle {
                            height: 72px;
                            Rectangle { y: parent.height * 0.5; height: 1px; background: #222233; }
                            GraphPath {
                                commands: root.area-commands;
                                fill: @linear-gradient(180deg, #ff000080 0%, #ff000000 100%);
                            }
                            GraphPath {
                                commands: root.line-commands;
                                stroke: root.tick == 0 ? #ff0000 : #0000ff;
                                stroke-width: 12px;
                                fill: #00000000;
                            }
                        }
                    }
                }
            }
        }

        public function open-menu() {
            menu.show();
        }
    }
}

struct TestPlatform(Rc<MinimalSoftwareWindow>);

impl Platform for TestPlatform {
    fn create_window_adapter(
        &self,
    ) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

const SCALE: f32 = 1.25;
const W: usize = 500; // 400 логических × 1.25
const H: usize = 375;

fn draw(window: &MinimalSoftwareWindow, buffer: &mut [Rgb8Pixel]) -> bool {
    slint::platform::update_timers_and_animations();
    window.draw_if_needed(|renderer| {
        renderer.render(buffer, W);
    })
}

fn px(buffer: &[Rgb8Pixel], x: usize, y: usize) -> (u8, u8, u8) {
    let p = buffer[y * W + x];
    (p.r, p.g, p.b)
}

/// Точка в физических пикселях из логических координат.
fn at(buffer: &[Rgb8Pixel], lx: f32, ly: f32) -> (u8, u8, u8) {
    px(buffer, (lx * SCALE) as usize, (ly * SCALE) as usize)
}

#[test]
fn popup_stays_on_top_of_partially_redrawn_content() {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(TestPlatform(window.clone()))).unwrap();

    let ui = TestWin::new().unwrap();
    window.set_size(slint::PhysicalSize::new(W as u32, H as u32));
    window.dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor: SCALE });

    // Пути, как их генерирует Rust: линия и заливка до низа, в пикселях
    // элемента (вьюбокс 1:1 с размером).
    ui.set_line_commands("M 0 30 L 380 30".into());
    ui.set_area_commands("M 0 30 L 380 30 L 380 72 L 0 72 Z".into());

    ui.show().unwrap();

    let mut buffer = vec![Rgb8Pixel::new(0, 0, 0); W * H];

    // Первый кадр: меню закрыто, график на месте. Карточка графика начинается
    // на y = 8 (padding) + 24 (picker) + 40 (прокладка) = 72, Path — ниже
    // подписи (16px), то есть с y = 88; линия tick=0 лежит на y ≈ 88 + 30.
    assert!(draw(&window, &mut buffer), "первый кадр обязан отрисоваться");
    assert_eq!(at(&buffer, 300.0, 118.0), (255, 0, 0), "линия графика до открытия меню");

    // Открыли меню: оно накрывает карточку графика (попап x=8..208, y=36..236).
    ui.invoke_open_menu();
    assert!(draw(&window, &mut buffer), "кадр с попапом обязан отрисоваться");
    assert_eq!(at(&buffer, 100.0, 118.0), (0, 255, 0), "попап поверх графика");

    // Отсчёт трафика: пик и линия перерисовались, как в render_traffic —
    // новые commands обоих путей. Под попапом их видно быть не должно —
    // именно так график «проступал» сквозь меню на «Обзоре».
    ui.set_tick(1);
    ui.set_line_commands("M 0 40 L 380 40".into());
    ui.set_area_commands("M 0 40 L 380 40 L 380 72 L 0 72 Z".into());
    assert!(draw(&window, &mut buffer), "кадр с новым графиком обязан отрисоваться");
    assert_eq!(at(&buffer, 300.0, 128.0), (0, 0, 255), "вне попапа график обновился");
    assert_eq!(
        at(&buffer, 100.0, 128.0),
        (0, 255, 0),
        "под попапом графика быть не должно"
    );
    assert_eq!(
        at(&buffer, 100.0, 46.0),
        (0, 255, 0),
        "подпись пика не должна пробивать меню"
    );
}
