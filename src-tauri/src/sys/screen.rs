//! A picture of the whole desktop, for «scan the QR code from the screen».
//!
//! Every backend narrows down to the same thing — a greyscale plane for
//! `qr::decode_luma` — because nothing downstream cares how the pixels were
//! obtained. What differs is who owns the screen: Windows hands out a device
//! context, GTK hands out the root window and refuses under Wayland, and macOS
//! keeps it behind a permission the system asks for on our behalf, which is
//! why there it goes through `screencapture` rather than a private framework.

use crate::error::{AppError, Result};

/// A captured screen, already reduced to luminance.
pub struct Shot {
    pub width: usize,
    pub height: usize,
    pub luma: Vec<u8>,
}

/// Grab every screen the desktop spans.
///
/// The caller is expected to have hidden the app's own window first: the
/// scanner is opened on top of whatever shows the code.
///
/// Async because on Linux the grab may only happen on the GTK thread, and the
/// command that calls this does not run there.
pub async fn capture<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<Vec<Shot>> {
    let _ = app;
    #[cfg(target_os = "linux")]
    {
        // GDK is not thread-safe, and the root window belongs to the loop that
        // drives the app's own windows.
        let (tx, rx) = tokio::sync::oneshot::channel();
        app.run_on_main_thread(move || {
            let _ = tx.send(linux_capture());
        })
        .map_err(|e| AppError::msg(format!("снимок экрана: {e}")))?;
        rx.await
            .map_err(|_| AppError::msg("снимок экрана: поток интерфейса не ответил"))?
    }
    #[cfg(not(target_os = "linux"))]
    {
        tokio::task::spawn_blocking(blocking_capture)
            .await
            .map_err(|e| AppError::msg(format!("снимок экрана: {e}")))?
    }
}

#[cfg(not(target_os = "linux"))]
fn blocking_capture() -> Result<Vec<Shot>> {
    #[cfg(windows)]
    {
        windows_capture().map(|shot| vec![shot])
    }
    #[cfg(target_os = "macos")]
    {
        macos_capture()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(AppError::msg(
            "снимок экрана на этой системе не поддерживается",
        ))
    }
}

/// The whole virtual desktop in one shot — `SM_*VIRTUALSCREEN` spans every
/// monitor, so a code on the second one is found just as well.
#[cfg(windows)]
fn windows_capture() -> Result<Shot> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC,
        SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    unsafe {
        let left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if width <= 0 || height <= 0 {
            return Err(AppError::msg("не удалось определить размер экрана"));
        }

        let screen = GetDC(None);
        if screen.is_invalid() {
            return Err(AppError::msg("экран недоступен"));
        }
        // Everything below has to be released whichever way this ends, so the
        // handles are dropped in reverse order at every exit.
        let result = (|| -> Result<Shot> {
            let memory = CreateCompatibleDC(Some(screen));
            if memory.is_invalid() {
                return Err(AppError::msg("не удалось создать контекст рисования"));
            }
            let out = (|| -> Result<Shot> {
                let info = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: width,
                        // Negative height: rows top-down, the order every
                        // consumer here expects. A DIB is bottom-up otherwise.
                        biHeight: -height,
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB.0,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
                let bitmap = CreateDIBSection(Some(memory), &info, DIB_RGB_COLORS, &mut bits, None, 0)
                    .map_err(|e| AppError::msg(format!("не удалось выделить снимок: {e}")))?;
                let previous = SelectObject(memory, bitmap.into());
                let copied = BitBlt(
                    memory, 0, 0, width, height, Some(screen), left, top, SRCCOPY,
                );
                let (width, height) = (width as usize, height as usize);
                let shot = match copied {
                    // BGRA out of GDI, rows packed tight; the alpha byte is
                    // undefined here and takes no part in luminance anyway.
                    Ok(()) if !bits.is_null() => {
                        let pixels =
                            std::slice::from_raw_parts(bits as *const u8, width * height * 4);
                        crate::qr::luma_from_pixels(width, height, width * 4, 4, pixels, true)
                            .map(|luma| Shot { width, height, luma })
                            .ok_or_else(|| AppError::msg("снимок экрана пришёл обрезанным"))
                    }
                    _ => Err(AppError::msg("не удалось снять экран")),
                };
                SelectObject(memory, previous);
                let _ = DeleteObject(bitmap.into());
                shot
            })();
            let _ = DeleteDC(memory);
            out
        })();
        ReleaseDC(Some(HWND::default()), screen);
        result
    }
}

/// X11 only: `gdk_pixbuf_get_from_window` is how a GTK app has always read the
/// screen, and under Wayland the compositor simply refuses — the file and
/// camera paths stay, so this reports the refusal instead of pretending.
#[cfg(target_os = "linux")]
fn linux_capture() -> Result<Vec<Shot>> {
    use gtk::gdk::prelude::*;

    let screen = gtk::gdk::Screen::default()
        .ok_or_else(|| AppError::msg("нет доступа к экрану"))?;
    let root = screen
        .root_window()
        .ok_or_else(|| AppError::msg("нет доступа к экрану"))?;
    let (width, height) = (root.width(), root.height());
    if width <= 0 || height <= 0 {
        return Err(AppError::msg("не удалось определить размер экрана"));
    }
    let pixbuf = root.pixbuf(0, 0, width, height).ok_or_else(|| {
        AppError::msg("снимок экрана недоступен — под Wayland сохраните картинку и выберите файл")
    })?;

    // A pixbuf is RGB or RGBA with a row stride of its own choosing.
    let (width, height) = (pixbuf.width() as usize, pixbuf.height() as usize);
    let luma = crate::qr::luma_from_pixels(
        width,
        height,
        pixbuf.rowstride() as usize,
        pixbuf.n_channels() as usize,
        &pixbuf.read_pixel_bytes(),
        false,
    )
    .ok_or_else(|| AppError::msg("снимок экрана пришёл в неизвестном виде"))?;
    Ok(vec![Shot {
        width,
        height,
        luma,
    }])
}

/// `screencapture` is the system's own tool, so the Screen Recording prompt
/// arrives in the app's name and the picture it produces is the one the user
/// sees. Displays are probed one by one: the tool refuses an index that does
/// not exist, which is also how the loop learns where to stop.
#[cfg(target_os = "macos")]
fn macos_capture() -> Result<Vec<Shot>> {
    /// Nobody has more; probing past the last display costs a failed process
    /// launch each time.
    const MAX_DISPLAYS: u8 = 4;

    let dir = std::env::temp_dir();
    let mut shots = Vec::new();
    let mut failure: Option<String> = None;

    for display in 1..=MAX_DISPLAYS {
        let path = dir.join(format!("aurora-qr-{}-{display}.png", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // -x: no shutter sound, this is not a screenshot the user asked to keep.
        let status = std::process::Command::new("/usr/sbin/screencapture")
            .args(["-x", "-t", "png", "-D"])
            .arg(display.to_string())
            .arg(&path)
            .status();
        let produced = matches!(status, Ok(code) if code.success()) && path.is_file();
        if !produced {
            if let Err(e) = status {
                failure = Some(e.to_string());
            }
            let _ = std::fs::remove_file(&path);
            break;
        }
        let read = std::fs::read(&path);
        let _ = std::fs::remove_file(&path);
        let picture = image::load_from_memory(&read?)
            .map_err(|e| AppError::msg(format!("снимок экрана: {e}")))?
            .to_luma8();
        shots.push(Shot {
            width: picture.width() as usize,
            height: picture.height() as usize,
            luma: picture.into_raw(),
        });
    }

    if shots.is_empty() {
        let reason = failure.unwrap_or_else(|| {
            "разрешите Aurora VPN запись экрана в «Конфиденциальность и безопасность»".into()
        });
        return Err(AppError::msg(format!("снимок экрана: {reason}")));
    }
    Ok(shots)
}
