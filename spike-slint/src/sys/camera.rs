//! Веб-камера как источник QR-кода.
//!
//! Media Foundation, без крейта-обёртки: набор Win32 у приложения уже свой, а
//! всё, что нужно от камеры, — список устройств и поток кадров в RGB32. Тяжёлую
//! часть — разбор NV12/YUY2, которыми камеры отдают картинку на самом деле, —
//! берёт на себя видеопроцессор самого Media Foundation: он включается
//! атрибутом `ENABLE_ADVANCED_VIDEO_PROCESSING`, после чего у читателя можно
//! просто попросить RGB32.
//!
//! Съёмка живёт в своём потоке: `ReadSample` блокирующий, а поток событий Slint
//! ждать кадр не может.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{AppError, Result};

/// Камера в списке выбора.
#[derive(Clone, Debug)]
pub struct Device {
    /// Символическая ссылка устройства — ею камера и открывается.
    pub id: String,
    pub name: String,
}

/// Кадр предпросмотра: цвет для картинки на экране, яркость для детектора.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    /// Плотно упакованный RGB сверху вниз, три байта на точку.
    pub rgb: Vec<u8>,
    pub luma: Vec<u8>,
}

/// Что съёмка сообщает наружу. Возврат `false` из приёмника останавливает
/// сессию — так закрывается окно, когда код уже прочитан.
pub enum Event {
    Frame(Frame),
    Failed(String),
}

/// Живая съёмка. Останавливается явно или собственным уничтожением: окно
/// закрылось — камера погасла, лампочка рядом с объективом тоже.
pub struct Session {
    stop: Arc<AtomicBool>,
}

impl Session {
    /// `device` — символическая ссылка из [`list`]; `None` берёт первую.
    pub fn start<F>(device: Option<String>, mut sink: F) -> Self
    where
        F: FnMut(Event) -> bool + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let spawned = std::thread::Builder::new()
            .name("qr-camera".into())
            .spawn(move || {
                if let Err(e) = capture(device, &flag, &mut sink) {
                    // Закрытое окно роняет чтение кадра — это не поломка.
                    if !flag.load(Ordering::Relaxed) {
                        sink(Event::Failed(e.to_string()));
                    }
                }
            });
        if spawned.is_err() {
            stop.store(true, Ordering::Relaxed);
        }
        Self { stop }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

// -------------------------------------------------------------- windows

/// Первый видеопоток источника. Значение из `mfreadwrite.h`; своей константой,
/// потому что в привязках оно живёт отдельным типом-обёрткой.
#[cfg(windows)]
const VIDEO_STREAM: u32 = 0xFFFF_FFFC;
#[cfg(windows)]
const ALL_STREAMS: u32 = 0xFFFF_FFFE;

/// Камеры, которые видит система, — в порядке, в котором их отдаёт система.
#[cfg(windows)]
pub fn list() -> Result<Vec<Device>> {
    use windows::Win32::Media::MediaFoundation::{
        MFStartup, MFSTARTUP_LITE, MF_VERSION,
    };

    unsafe {
        MFStartup(MF_VERSION, MFSTARTUP_LITE)
            .map_err(|e| AppError::msg(format!("Media Foundation недоступен: {e}")))?;
        let found = enumerate();
        let _ = windows::Win32::Media::MediaFoundation::MFShutdown();
        found
    }
}

/// Перебирает источники видеозахвата. Вызывать между `MFStartup`/`MFShutdown`.
#[cfg(windows)]
unsafe fn enumerate() -> Result<Vec<Device>> {
    use windows::Win32::Media::MediaFoundation::{
        IMFActivate, MFCreateAttributes, MFEnumDeviceSources,
        MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
    };
    use windows::Win32::System::Com::CoTaskMemFree;

    let mut attributes = None;
    MFCreateAttributes(&mut attributes, 1)
        .map_err(|e| AppError::msg(format!("камера: {e}")))?;
    let attributes = attributes.ok_or_else(|| AppError::msg("камера: пустые атрибуты"))?;
    attributes
        .SetGUID(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        )
        .map_err(|e| AppError::msg(format!("камера: {e}")))?;

    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    MFEnumDeviceSources(&attributes, &mut list, &mut count)
        .map_err(|e| AppError::msg(format!("не удалось перечислить камеры: {e}")))?;

    let mut devices = Vec::new();
    for index in 0..count as usize {
        // Массив принадлежит нам вместе со ссылками в нём: значение забирается
        // из ячейки и освобождается, уходя из области видимости.
        let Some(activate) = std::ptr::read(list.add(index)) else {
            continue;
        };
        let id = allocated_string(
            &activate,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
        );
        let name = allocated_string(&activate, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME);
        if let Some(id) = id {
            devices.push(Device {
                name: name.unwrap_or_else(|| "Камера".into()),
                id,
            });
        }
    }
    if !list.is_null() {
        CoTaskMemFree(Some(list as *const core::ffi::c_void));
    }
    // Пустой список — не ошибка: камеры может не быть вовсе, и сказать об этом
    // должен интерфейс, а не отказ откуда-то из глубины.
    Ok(devices)
}

/// Строковый атрибут, который система выделила сама и который нам же
/// возвращать её распределителю.
#[cfg(windows)]
unsafe fn allocated_string(
    activate: &windows::Win32::Media::MediaFoundation::IMFActivate,
    key: &windows::core::GUID,
) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::System::Com::CoTaskMemFree;

    let mut text = PWSTR::null();
    let mut length = 0u32;
    activate.GetAllocatedString(key, &mut text, &mut length).ok()?;
    if text.is_null() {
        return None;
    }
    let value = text.to_string().ok();
    CoTaskMemFree(Some(text.as_ptr() as *const core::ffi::c_void));
    value
}

/// Съёмка от начала до конца: своя инициализация COM, свой источник, свой цикл.
#[cfg(windows)]
fn capture<F>(device: Option<String>, stop: &AtomicBool, sink: &mut F) -> Result<()>
where
    F: FnMut(Event) -> bool,
{
    use windows::core::PCWSTR;
    use windows::Win32::Media::MediaFoundation::{
        IMFMediaSource, IMFSample, MFCreateAttributes, MFCreateDeviceSource, MFCreateMediaType,
        MFCreateSourceReaderFromMediaSource, MFMediaType_Video, MFShutdown, MFStartup,
        MFVideoFormat_RGB32, MFSTARTUP_LITE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE,
        MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED, MF_SOURCE_READERF_ENDOFSTREAM,
        MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING, MF_VERSION,
    };
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    unsafe {
        // Свой поток — свой апартмент. MTA: ничего оконного здесь нет, а
        // читатель отдаёт кадры из собственных рабочих потоков.
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        MFStartup(MF_VERSION, MFSTARTUP_LITE)
            .map_err(|e| AppError::msg(format!("Media Foundation недоступен: {e}")))?;

        let result = (|| -> Result<()> {
            let id = match device {
                Some(id) => id,
                None => enumerate()?
                    .into_iter()
                    .next()
                    .ok_or_else(|| AppError::msg("камера не найдена"))?
                    .id,
            };
            let wide: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();

            let mut attributes = None;
            MFCreateAttributes(&mut attributes, 2)
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;
            let attributes = attributes.ok_or_else(|| AppError::msg("камера: пустые атрибуты"))?;
            attributes
                .SetGUID(
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
                )
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;
            attributes
                .SetString(
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                    PCWSTR(wide.as_ptr()),
                )
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;

            let source: IMFMediaSource = MFCreateDeviceSource(&attributes)
                .map_err(|e| AppError::msg(format!("не удалось открыть камеру: {e}")))?;

            let mut reader_attributes = None;
            MFCreateAttributes(&mut reader_attributes, 1)
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;
            let reader_attributes =
                reader_attributes.ok_or_else(|| AppError::msg("камера: пустые атрибуты"))?;
            // Тот самый видеопроцессор: без него читатель отдаёт только то, что
            // умеет само устройство, а это почти всегда NV12 или YUY2.
            reader_attributes
                .SetUINT32(&MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING, 1)
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;

            let reader = MFCreateSourceReaderFromMediaSource(&source, &reader_attributes)
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;
            reader
                .SetStreamSelection(ALL_STREAMS, false)
                .and_then(|()| reader.SetStreamSelection(VIDEO_STREAM, true))
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;

            let wanted = MFCreateMediaType().map_err(|e| AppError::msg(format!("камера: {e}")))?;
            wanted
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .and_then(|()| wanted.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32))
                .map_err(|e| AppError::msg(format!("камера: {e}")))?;
            reader
                .SetCurrentMediaType(VIDEO_STREAM, None, &wanted)
                .map_err(|e| AppError::msg(format!("камера не отдаёт кадры в RGB: {e}")))?;

            let mut layout = read_layout(&reader)?;

            while !stop.load(Ordering::Relaxed) {
                let mut stream = 0u32;
                let mut flags = 0u32;
                let mut timestamp = 0i64;
                let mut sample: Option<IMFSample> = None;
                reader
                    .ReadSample(
                        VIDEO_STREAM,
                        0,
                        Some(&mut stream),
                        Some(&mut flags),
                        Some(&mut timestamp),
                        Some(&mut sample),
                    )
                    .map_err(|e| AppError::msg(format!("камера перестала отвечать: {e}")))?;

                if flags & MF_SOURCE_READERF_ENDOFSTREAM.0 as u32 != 0 {
                    break;
                }
                // Камера вправе сменить разрешение на ходу — например, когда
                // автоэкспозиция переключает режим.
                if flags & MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED.0 as u32 != 0 {
                    layout = read_layout(&reader)?;
                }
                // Пустая выборка — это ожидание, а не конец: читатель так
                // отвечает, пока устройство раскручивается.
                let Some(sample) = sample else { continue };

                let Some(frame) = frame_from(&sample, &layout) else {
                    continue;
                };
                if !sink(Event::Frame(frame)) {
                    break;
                }
            }
            Ok(())
        })();

        let _ = MFShutdown();
        CoUninitialize();
        result
    }
}

/// Размер кадра и шаг строки, как их объявляет текущий тип потока.
#[cfg(windows)]
struct Layout {
    width: u32,
    height: u32,
    /// Со знаком: отрицательный шаг значит, что строки в буфере снизу вверх.
    stride: i32,
}

#[cfg(windows)]
unsafe fn read_layout(
    reader: &windows::Win32::Media::MediaFoundation::IMFSourceReader,
) -> Result<Layout> {
    use windows::Win32::Media::MediaFoundation::{MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_SIZE};

    let current = reader
        .GetCurrentMediaType(VIDEO_STREAM)
        .map_err(|e| AppError::msg(format!("камера: {e}")))?;
    let packed = current
        .GetUINT64(&MF_MT_FRAME_SIZE)
        .map_err(|e| AppError::msg(format!("камера не сообщила размер кадра: {e}")))?;
    let width = (packed >> 32) as u32;
    let height = packed as u32;
    if width == 0 || height == 0 {
        return Err(AppError::msg("камера сообщила пустой кадр"));
    }
    // Атрибута может не быть: у несжатого RGB порядок строк тогда снизу вверх,
    // как у DIB, — это и есть отрицательный шаг.
    let stride = match current.GetUINT32(&MF_MT_DEFAULT_STRIDE) {
        Ok(value) => value as i32,
        Err(_) => -((width as i32) * 4),
    };
    Ok(Layout {
        width,
        height,
        stride,
    })
}

/// Выборка → кадр. `None`, если буфер короче объявленного кадра: лучше
/// пропустить кадр, чем читать за его краем.
#[cfg(windows)]
unsafe fn frame_from(
    sample: &windows::Win32::Media::MediaFoundation::IMFSample,
    layout: &Layout,
) -> Option<Frame> {
    let buffer = sample.ConvertToContiguousBuffer().ok()?;
    let mut data: *mut u8 = std::ptr::null_mut();
    let mut length = 0u32;
    buffer.Lock(&mut data, None, Some(&mut length)).ok()?;

    let frame = (|| {
        if data.is_null() {
            return None;
        }
        let pixels = std::slice::from_raw_parts(data as *const u8, length as usize);
        let (width, height) = (layout.width as usize, layout.height as usize);
        let step = layout.stride.unsigned_abs() as usize;
        if step < width * 4 || pixels.len() < (height - 1) * step + width * 4 {
            return None;
        }

        // Строки укладываются сверху вниз и плотно, каким бы ни был шаг в
        // буфере: перевёрнутый кадр — это зеркальный код, а зеркальный код не
        // читает ни один декодер.
        let mut rgb = Vec::with_capacity(width * height * 3);
        for y in 0..height {
            let source = if layout.stride < 0 { height - 1 - y } else { y };
            let row = &pixels[source * step..];
            for x in 0..width {
                let pixel = &row[x * 4..];
                rgb.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
            }
        }
        let luma = crate::qr::luma_from_pixels(width, height, width * 3, 3, &rgb, false)?;
        Some(Frame {
            width: layout.width,
            height: layout.height,
            rgb,
            luma,
        })
    })();

    let _ = buffer.Unlock();
    frame
}

// ------------------------------------------------------------ не windows

#[cfg(not(windows))]
pub fn list() -> Result<Vec<Device>> {
    Err(AppError::msg("камера доступна только под Windows"))
}

#[cfg(not(windows))]
fn capture<F>(_device: Option<String>, _stop: &AtomicBool, _sink: &mut F) -> Result<()>
where
    F: FnMut(Event) -> bool,
{
    Err(AppError::msg("камера доступна только под Windows"))
}
