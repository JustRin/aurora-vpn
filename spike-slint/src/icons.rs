//! Настоящие иконки программ для списков раздельного туннеля.
//!
//! Квадратик с первой буквой имени процесса — заглушка: у каждого .exe своя
//! иконка лежит прямо в ресурсах файла. `PrivateExtractIconsW` выбирает из них
//! картинку ближе всего к запрошенному размеру и отдаёт готовый `HICON`;
//! дальше иконка разбирается на пиксели (`GetDIBits`) и, если размер не совпал,
//! усредняется до нужного.
//!
//! Масштабировать её средствами Slint нельзя: софтверный рендер тянет картинки
//! ближайшим соседом (i-slint-renderer-software, draw_functions.rs —
//! `fetch_blend_pixel` берёт от позиции целую часть и выбрасывает дробную), так
//! что иконка 32×32 в боксе 30×30 потеряла бы два ряда пикселей целиком, а на
//! рисунке такого размера это видно сразу. Поэтому наружу уходит изображение
//! ровно в тех физических пикселях, которыми оно и будет нарисовано.
//!
//! Чтение ресурсов чужого .exe — это поход на диск: на списке в пару сотен
//! процессов набегают заметные доли секунды прямо в кадре. Поэтому добыча
//! живёт на отдельном потоке, а UI спрашивает только кэш и получает `None`,
//! пока иконки нет, — строка в это время рисует букву.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Sender};
use std::sync::{LazyLock, Mutex, OnceLock};

/// Заявка потоку. `key` — под каким ключом класть результат; `path` — путь к
/// .exe, он может быть пустым или уже несуществующим; `name` — имя процесса на
/// этот случай: правило раздельного туннеля ловит программу как раз по имени,
/// чтобы пережить обновление с переездом бинарника в новую папку.
struct Job {
    key: String,
    name: String,
    path: String,
    size: u32,
}

#[derive(Default)]
struct Store {
    /// Ключ → пиксели RGBA с предумноженной альфой. `None` — иконки нет:
    /// второй раз идти на диск за тем же ответом незачем.
    done: HashMap<String, Option<Vec<u8>>>,
    /// Ключи, уже отданные потоку. Список процессов перестраивается на каждую
    /// букву в строке поиска, и без этого одна иконка встала бы в очередь
    /// десяток раз.
    queued: HashSet<String>,
}

static STORE: LazyLock<Mutex<Store>> = LazyLock::new(|| Mutex::new(Store::default()));
static JOBS: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();

/// Запускает поток-добытчик. `notify` зовётся из него каждый раз, когда в кэше
/// появилась очередная пачка, — по этому сигналу UI перечитывает кэш.
pub fn init(notify: impl Fn() + Send + 'static) {
    let (tx, rx) = mpsc::channel::<Job>();
    if JOBS.set(Mutex::new(tx)).is_err() {
        return;
    }
    let worker = move || {
        // Одна пачка — одно пробуждение UI: при первом показе списка сюда
        // прилетает сразу сотня заявок, и будить событийный цикл на каждую
        // значило бы сотню лишних перерисовок.
        const BATCH: usize = 32;
        while let Ok(first) = rx.recv() {
            let mut jobs = vec![first];
            while jobs.len() < BATCH {
                match rx.try_recv() {
                    Ok(job) => jobs.push(job),
                    Err(_) => break,
                }
            }
            // Таблица запущенного строится лениво и живёт ровно одну пачку:
            // нужна она только заявкам без пути, а к следующей пачке список
            // процессов всё равно успевает измениться.
            let mut running: Option<HashMap<String, String>> = None;
            let ready: Vec<(String, Option<Vec<u8>>)> = jobs
                .into_iter()
                .map(|job| {
                    let mut bits = if job.path.is_empty() {
                        None
                    } else {
                        extract(&job.path, job.size)
                    };
                    if bits.is_none() && !job.name.is_empty() {
                        let table = running.get_or_insert_with(running_paths);
                        if let Some(path) = table.get(&job.name.to_lowercase()) {
                            bits = extract(path, job.size);
                        }
                    }
                    (job.key, bits)
                })
                .collect();
            if let Ok(mut store) = STORE.lock() {
                store.done.extend(ready);
            }
            notify();
        }
    };
    std::thread::Builder::new()
        .name("icons".into())
        .spawn(worker)
        .expect("не удалось запустить поток иконок");
}

/// Иконка для строки списка стороной `size` в физических пикселях. `None` —
/// либо её ещё нет (тогда файл встаёт в очередь и придёт со следующим
/// `notify`), либо у него её и не будет.
pub fn get(name: &str, path: &str, size: u32) -> Option<slint::Image> {
    if name.is_empty() && path.is_empty() {
        return None;
    }
    // Размер в ключе: после смены DPI иконки нужны в других пикселях, а старые
    // остаются лежать рядом — на обратном пути к прежнему масштабу они не
    // потребуют второго похода на диск.
    let key = format!(
        "{size}|{}",
        if path.is_empty() { name } else { path }.to_lowercase()
    );
    let mut store = STORE.lock().ok()?;
    if let Some(bits) = store.done.get(&key) {
        return bits
            .as_deref()
            .filter(|bits| bits.len() == (size * size * 4) as usize)
            .map(|bits| to_image(bits, size));
    }
    if !store.queued.insert(key.clone()) {
        return None;
    }
    drop(store);
    if let Some(jobs) = JOBS.get() {
        let job = Job { key, name: name.into(), path: path.into(), size };
        let _ = jobs.lock().map(|jobs| jobs.send(job));
    }
    None
}

fn to_image(bits: &[u8], size: u32) -> slint::Image {
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(size, size);
    buffer.make_mut_bytes().copy_from_slice(bits);
    slint::Image::from_rgba8_premultiplied(buffer)
}

/// Имя процесса (в нижнем регистре) → путь к его .exe. Нужна правилам, которые
/// ловят программу по имени: пути у них нет, а иконку показать надо.
fn running_paths() -> HashMap<String, String> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let mut table: HashMap<String, String> = HashMap::new();
    for process in sys.processes().values() {
        let Some(exe) = process.exe() else { continue };
        let Some(name) = exe.file_name() else { continue };
        table
            .entry(name.to_string_lossy().to_lowercase())
            .or_insert_with(|| exe.to_string_lossy().to_string());
    }
    table
}

#[cfg(not(windows))]
fn extract(_path: &str, _size: u32) -> Option<Vec<u8>> {
    None
}

/// Иконка файла стороной ровно `size` пикселей.
#[cfg(windows)]
fn extract(path: &str, size: u32) -> Option<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, PrivateExtractIconsW, HICON};

    // Размеры, которые художники кладут в .ico. Просить нестандартные 30 или 45
    // смысла нет: система всё равно возьмёт ближайший ресурс и растянет его
    // своим масштабированием — а усреднить лишние пиксели мы умеем и сами.
    const NATIVE: [u32; 10] = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256];

    let side = NATIVE.iter().copied().find(|n| *n >= size).unwrap_or(256);
    let wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut icon: HICON = std::ptr::null_mut();
    // nicons = 1: берём первую иконку файла — ту же, что показывает проводник.
    let got = unsafe {
        PrivateExtractIconsW(
            wide.as_ptr(),
            0,
            side as i32,
            side as i32,
            &mut icon,
            std::ptr::null_mut(),
            1,
            0,
        )
    };
    if got != 1 || icon.is_null() {
        return None;
    }
    let pixels = unsafe { icon_pixels(icon) };
    unsafe { DestroyIcon(icon) };

    let (bits, w, h) = pixels?;
    Some(if w == size && h == size {
        bits
    } else {
        shrink(&bits, w, h, size)
    })
}

/// Разбирает `HICON` на RGBA с предумноженной альфой.
#[cfg(windows)]
unsafe fn icon_pixels(
    icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
) -> Option<(Vec<u8>, u32, u32)> {
    use windows_sys::Win32::Graphics::Gdi::DeleteObject;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};

    let mut info: ICONINFO = std::mem::zeroed();
    if GetIconInfo(icon, &mut info) == 0 {
        return None;
    }
    let pixels = bitmap_pixels(info.hbmColor, info.hbmMask);
    if !info.hbmColor.is_null() {
        DeleteObject(info.hbmColor);
    }
    if !info.hbmMask.is_null() {
        DeleteObject(info.hbmMask);
    }
    pixels
}

#[cfg(windows)]
unsafe fn bitmap_pixels(
    color: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    mask: windows_sys::Win32::Graphics::Gdi::HBITMAP,
) -> Option<(Vec<u8>, u32, u32)> {
    use windows_sys::Win32::Graphics::Gdi::{GetObjectW, BITMAP};

    // Чёрно-белые иконки времён до XP (одна маска, без цветного слоя) в списке
    // процессов не встречаются — разбирать их отдельным путём незачем.
    if color.is_null() {
        return None;
    }
    let mut bmp: BITMAP = std::mem::zeroed();
    if GetObjectW(
        color,
        std::mem::size_of::<BITMAP>() as i32,
        (&mut bmp as *mut BITMAP).cast(),
    ) == 0
    {
        return None;
    }
    if bmp.bmWidth <= 0 || bmp.bmHeight <= 0 {
        return None;
    }
    let (w, h) = (bmp.bmWidth as u32, bmp.bmHeight as u32);

    let mut pixels = read_dib(color, w, h)?;
    // У 24-битных иконок (старые программы и часть системных) альфа нулевая, а
    // прозрачность живёт в отдельной маске: где её пиксель белый — иконки нет.
    if pixels.chunks_exact(4).all(|px| px[3] == 0) {
        let mask = read_dib(mask, w, h)?;
        for (px, m) in pixels.chunks_exact_mut(4).zip(mask.chunks_exact(4)) {
            px[3] = if m[0] == 0 { 255 } else { 0 };
        }
    }
    // BGRA → RGBA, попутно предумножая: усреднять при уменьшении можно только
    // предумноженные пиксели, иначе прозрачные подмешивают в края свой цвет.
    for px in pixels.chunks_exact_mut(4) {
        let a = px[3] as u16;
        let (b, g, r) = (px[0] as u16, px[1] as u16, px[2] as u16);
        px[0] = (r * a / 255) as u8;
        px[1] = (g * a / 255) as u8;
        px[2] = (b * a / 255) as u8;
    }
    Some((pixels, w, h))
}

/// Пиксели GDI-битмапа как BGRA, строками сверху вниз.
#[cfg(windows)]
unsafe fn read_dib(
    bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    w: u32,
    h: u32,
) -> Option<Vec<u8>> {
    use windows_sys::Win32::Graphics::Gdi::{
        GetDC, GetDIBits, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
    };

    if bitmap.is_null() {
        return None;
    }
    let mut header: BITMAPINFO = std::mem::zeroed();
    header.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: w as i32,
        // Минус — строки сверху вниз: DIB по умолчанию хранит их снизу вверх.
        biHeight: -(h as i32),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    let mut pixels = vec![0u8; w as usize * h as usize * 4];
    let dc = GetDC(std::ptr::null_mut());
    let lines = GetDIBits(
        dc,
        bitmap,
        0,
        h,
        pixels.as_mut_ptr().cast(),
        &mut header,
        DIB_RGB_COLORS,
    );
    ReleaseDC(std::ptr::null_mut(), dc);
    (lines != 0).then_some(pixels)
}

/// Уменьшение до стороны `size`: пиксель результата — среднее того
/// прямоугольника исходника, который в него попал.
#[cfg(windows)]
fn shrink(src: &[u8], sw: u32, sh: u32, size: u32) -> Vec<u8> {
    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        let y0 = (y * sh / size) as usize;
        let y1 = ((y + 1) * sh).div_ceil(size).clamp(y0 as u32 + 1, sh) as usize;
        for x in 0..size {
            let x0 = (x * sw / size) as usize;
            let x1 = ((x + 1) * sw).div_ceil(size).clamp(x0 as u32 + 1, sw) as usize;
            let mut acc = [0u32; 4];
            for row in y0..y1 {
                for col in x0..x1 {
                    let p = (row * sw as usize + col) * 4;
                    for (sum, c) in acc.iter_mut().zip(&src[p..p + 4]) {
                        *sum += *c as u32;
                    }
                }
            }
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            let p = ((y * size + x) * 4) as usize;
            for (dst, sum) in out[p..p + 4].iter_mut().zip(acc) {
                *dst = (sum / n) as u8;
            }
        }
    }
    out
}
