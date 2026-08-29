//! Тот же сценарий, что в popup_partial.rs, но на настоящей разметке
//! «Обзора»: раскрытый выбор сервера и график, обновляющийся под ним.
//!
//! Ни одной захардкоженной координаты: кадры сравниваются между собой.
//! Сначала выясняется, какие пиксели меняет отсчёт трафика (это график и
//! подпись пика), затем меню накрывает часть из них — и после следующего
//! отсчёта под меню не должно измениться ничего.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter, WindowEvent};
use slint::{ModelRc, Rgb8Pixel, VecModel};

slint::slint! {
    import { DashboardPage } from "ui/pages/dashboard.slint";
    export { Data, Conf, Ui } from "ui/data.slint";

    export component RealDash inherits Window {
        width: 850px;
        height: 600px;
        background: #0b0c14;
        dash := DashboardPage { }
        public function open-picker() {
            dash.open-picker();
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
const W: usize = (850.0 * SCALE) as usize;
const H: usize = (600.0 * SCALE) as usize;

/// Прогнать кадры, пока окну есть что рисовать: даёт анимациям (подсветка
/// пикера, раскрытие меню) дойти до конца, чтобы снимки были стабильными.
fn settle(window: &MinimalSoftwareWindow, buffer: &mut [Rgb8Pixel]) {
    for _ in 0..120 {
        slint::platform::update_timers_and_animations();
        let drew = window.draw_if_needed(|renderer| {
            renderer.render(buffer, W);
        });
        if !drew && !window.window().has_active_animations() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn node(id: &str, name: &str) -> ServerNode {
    ServerNode {
        id: id.into(),
        name: name.into(),
        proto: "VLESS".into(),
        transport: "REALITY".into(),
        address: "1.2.3.4".into(),
        country: "NL".into(),
        latency: "171 мс".into(),
        tier: "good".into(),
    }
}

/// Пути графика в пикселях элемента, как их генерирует main.rs: линия на
/// высоте `y` и заливка от неё до низа.
fn graph_paths(data: &Data, width: f32, y: f32) {
    data.set_graph_down_line(format!("M 20 {y} L {} {y}", width - 20.0).into());
    data.set_graph_down_area(
        format!("M 20 {y} L {w} {y} L {w} 71 L 20 71 Z", w = width - 20.0).into(),
    );
    data.set_graph_up_line(format!("M 20 {yy} L {} {yy}", width - 20.0, yy = y + 6.0).into());
    data.set_graph_up_area("".into());
}

#[test]
fn dashboard_popup_survives_traffic_ticks() {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(TestPlatform(window.clone()))).unwrap();

    let ui = RealDash::new().unwrap();
    window.set_size(slint::PhysicalSize::new(W as u32, H as u32));
    window.dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor: SCALE });

    let data = ui.global::<Data>();
    let nodes: Vec<ServerNode> = (0..6)
        .map(|i| node(&format!("id{i}"), &format!("node-{i}")))
        .collect();
    data.set_nodes(ModelRc::new(VecModel::from(nodes)));
    data.set_active_id("id0".into());
    data.set_active_label("NL · VLESS · node-0".into());
    data.set_active_latency("171 мс".into());
    data.set_active_tier("good".into());
    data.set_connected(true);
    data.set_elevated(true);
    data.set_state_text("Подключено".into());
    data.set_uptime("00:01:00".into());
    data.set_down_rate("256.9 КБ/с".into());
    data.set_up_rate("4.18 КБ/с".into());
    data.set_peak("пик 342.2 КБ/с".into());

    // Ширина графика — во всю карточку героя: окно минус отступы страницы.
    let graph_w = 850.0 - 2.0 * 28.0;
    data.set_graph_w(graph_w);
    graph_paths(&data, graph_w, 30.0);

    ui.show().unwrap();

    let mut frame = vec![Rgb8Pixel::new(0, 0, 0); W * H];
    settle(&window, &mut frame);
    let before_tick = frame.clone();

    // Отсчёт трафика до открытия меню: какие пиксели он трогает.
    graph_paths(&data, graph_w, 44.0);
    data.set_peak("пик 351.0 КБ/с".into());
    data.set_uptime("00:01:01".into());
    settle(&window, &mut frame);
    let dynamic: Vec<usize> = (0..W * H)
        .filter(|&i| frame[i] != before_tick[i])
        .collect();
    assert!(
        dynamic.len() > 500,
        "отсчёт должен перерисовать график, а изменилось {} пикселей",
        dynamic.len()
    );

    // Раскрыли выбор сервера. Всё из «динамики», что поменяло цвет при
    // неизменном графике, накрыто меню.
    let before_menu = frame.clone();
    ui.invoke_open_picker();
    settle(&window, &mut frame);
    let covered: Vec<usize> =
        dynamic.iter().copied().filter(|&i| frame[i] != before_menu[i]).collect();
    assert!(
        covered.len() > 200,
        "меню должно накрывать график, а накрыло {} динамичных пикселей",
        covered.len()
    );

    // Очередной отсчёт при открытом меню: под меню не должен измениться ни
    // один пиксель — именно здесь график «проступал» сквозь список серверов.
    let stable = frame.clone();
    graph_paths(&data, graph_w, 30.0);
    if std::env::var_os("BISECT_NO_TEXT").is_none() {
        data.set_peak("пик 342.2 КБ/с".into());
        data.set_uptime("00:01:02".into());
    }
    settle(&window, &mut frame);
    let leaked: Vec<usize> = covered.iter().copied().filter(|&i| frame[i] != stable[i]).collect();
    if let Some(dir) = std::env::var_os("DUMP_FRAMES") {
        let dir = std::path::PathBuf::from(dir);
        for (name, buf) in [
            ("before-tick", &before_tick),
            ("before-menu", &before_menu),
            ("with-menu", &stable),
            ("after-tick", &frame),
        ] {
            let mut out = format!("P6\n{W} {H}\n255\n").into_bytes();
            for p in buf.iter() {
                out.extend_from_slice(&[p.r, p.g, p.b]);
            }
            std::fs::write(dir.join(format!("{name}.ppm")), out).unwrap();
        }
    }
    let bbox = |set: &[usize]| {
        let (mut x0, mut y0, mut x1, mut y1) = (usize::MAX, usize::MAX, 0usize, 0usize);
        for &i in set {
            let (x, y) = (i % W, i / W);
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
        }
        (x0, y0, x1, y1)
    };
    if !leaked.is_empty() {
        let mut rows: std::collections::BTreeMap<usize, usize> = Default::default();
        for &i in &leaked {
            *rows.entry(i / W).or_default() += 1;
        }
        eprintln!("строки утечки (физ. y → пикселей): {rows:?}");
    }
    assert_eq!(
        leaked.len(),
        0,
        "график проступил сквозь меню: {} из {} накрытых пикселей перерисованы; \
         утечка bbox={:?}, меню bbox={:?} (физические пиксели, ×{SCALE})",
        leaked.len(),
        covered.len(),
        bbox(&leaked),
        bbox(&covered)
    );
}
