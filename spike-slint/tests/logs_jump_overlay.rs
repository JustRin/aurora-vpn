//! Кнопка «К последним записям» — оверлей поверх журнала.
//!
//! Появление кнопки не должно менять раскладку (высоту ленты), а само
//! появление и исчезновение — плавные: между «нет» и «есть» обязаны быть
//! кадры, отличающиеся и от исходного, и от конечного состояния.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ModelRc, Rgb8Pixel, VecModel};

slint::slint! {
    import { LogsPage } from "ui/pages/logs.slint";
    export { Data, Ui } from "ui/data.slint";

    export component LogsShell inherits Window {
        width: 850px;
        height: 600px;
        background: #0b0c14;
        LogsPage { }
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

const W: usize = 850;
const H: usize = 600;

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

fn differs(a: &[Rgb8Pixel], b: &[Rgb8Pixel]) -> bool {
    a.iter().zip(b).any(|(x, y)| x != y)
}

/// Прогнать анимацию до конца, собирая каждый отрисованный кадр.
/// Возвращает все кадры; последний — устоявшееся состояние.
fn capture_transition(
    window: &MinimalSoftwareWindow,
    buffer: &mut [Rgb8Pixel],
) -> Vec<Vec<Rgb8Pixel>> {
    let mut frames: Vec<Vec<Rgb8Pixel>> = Vec::new();
    for _ in 0..200 {
        slint::platform::update_timers_and_animations();
        let drew = window.draw_if_needed(|renderer| {
            renderer.render(buffer, W);
        });
        if drew {
            frames.push(buffer.to_vec());
        } else if !window.window().has_active_animations() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    frames
}

/// Есть ли среди кадров перехода хотя бы один, не совпадающий ни с началом,
/// ни с концом, — то есть анимация действительно рисует промежуточные фазы.
fn has_intermediate(frames: &[Vec<Rgb8Pixel>], from: &[Rgb8Pixel], to: &[Rgb8Pixel]) -> bool {
    frames.iter().any(|f| differs(f, from) && differs(f, to))
}

#[test]
fn jump_button_overlays_the_log_view_and_fades() {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(TestPlatform(window.clone()))).unwrap();

    let ui = LogsShell::new().unwrap();
    window.set_size(slint::PhysicalSize::new(W as u32, H as u32));

    let data = ui.global::<Data>();
    let lines: Vec<LogLine> = (0..200)
        .map(|i| LogLine {
            level: "info".into(),
            text: format!("[{i}] inbound/tun[tun-in]: inbound connection from 172.19.0.1").into(),
        })
        .collect();
    data.set_logs(ModelRc::new(VecModel::from(lines)));
    ui.global::<Ui>().set_log_follow(true);

    ui.show().unwrap();

    let mut frame = vec![Rgb8Pixel::new(0, 0, 0); W * H];
    settle(&window, &mut frame);
    let following = frame.clone();

    // Пользователь отмотал вверх — кнопка появляется.
    ui.global::<Ui>().set_log_follow(false);
    let frames_in = capture_transition(&window, &mut frame);
    settle(&window, &mut frame);
    let shown = frame.clone();

    if let Some(dir) = std::env::var_os("DUMP_FRAMES") {
        let dir = std::path::PathBuf::from(dir);
        let mid = &frames_in[frames_in.len() / 2];
        for (name, buf) in
            [("logs-following", &following), ("logs-mid-in", mid), ("logs-shown", &shown)]
        {
            let mut out = format!("P6\n{W} {H}\n255\n").into_bytes();
            for p in buf.iter() {
                out.extend_from_slice(&[p.r, p.g, p.b]);
            }
            std::fs::write(dir.join(format!("{name}.ppm")), out).unwrap();
        }
    }

    let appeared: Vec<usize> = (0..W * H).filter(|&i| shown[i] != following[i]).collect();
    assert!(!appeared.is_empty(), "кнопка обязана появиться");

    // Раскладка не дёрнулась: перерисовалась только зона кнопки в нижней
    // части ленты, строки журнала выше стоят как стояли.
    let min_y = appeared.iter().map(|i| i / W).min().unwrap();
    assert!(
        min_y > H / 2,
        "появление кнопки перерисовало верх страницы (y={min_y}) — раскладка сдвинулась"
    );

    assert!(
        has_intermediate(&frames_in, &following, &shown),
        "нет переходных кадров — появление мгновенно"
    );

    // Исчезновение тоже плавное, и в конце кадр совпадает с исходным.
    ui.global::<Ui>().set_log_follow(true);
    let frames_out = capture_transition(&window, &mut frame);
    settle(&window, &mut frame);
    assert!(
        has_intermediate(&frames_out, &shown, &frame),
        "нет переходных кадров — исчезновение мгновенно"
    );
    assert_eq!(
        (0..W * H).filter(|&i| frame[i] != following[i]).count(),
        0,
        "после исчезновения кадр обязан совпасть с исходным"
    );
}
