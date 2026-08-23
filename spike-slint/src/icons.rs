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
//!
//! У строк раздельного туннеля есть только имя процесса: правило ловит
//! программу по нему, чтобы пережить обновление с переездом бинарника. Путь к
//! .exe для такой строки берётся из таблицы запущенного — а значит пропадает
//! вместе с программой. Клиент, поднятый автозапуском раньше браузера и почты,
//! не находил ни одной и рисовал буквы весь сеанс. Поэтому раз добытая иконка
//! остаётся на диске (`keep`): в записи лежит и путь, по которому её взяли, —
//! по нему картинка перечитывается в любом размере, — и её снимок 96×96 на тот
//! случай, если программу успели снести или обновление увело её в другую папку.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{LazyLock, Mutex, OnceLock};

/// Сторона снимка, который остаётся на диске. 96 — «родной» размер иконки,
/// которого хватает строке в 30 точек даже на трёхкратном масштабе экрана.
const KEEP_SIDE: u32 = 96;
/// Сколько записей держать в папке. Строку из списка удаляют, а её файл
/// остаётся — этот предел не даёт папке расти без конца.
const KEEP_LIMIT: usize = 128;

/// Заявка потоку. `key` — под каким ключом класть результат; `path` — путь к
/// .exe, он может быть пустым или уже несуществующим; `name` — имя процесса на
/// этот случай: правило раздельного туннеля ловит программу как раз по имени,
/// чтобы пережить обновление с переездом бинарника в новую папку.
struct Job {
    key: String,
    name: String,
    path: String,
    size: u32,
    /// Строка списка раздельного туннеля: её иконку надо сохранить на диск и
    /// оттуда же брать, когда программы нет ни на месте, ни в живых. Строкам
    /// окна «Запущенные приложения» это не нужно — их путь всегда настоящий, а
    /// самих строк сотни.
    keep: bool,
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
/// Папка с сохранёнными иконками. Пусто — сохранять некуда, и всё работает
/// как прежде: живая добыча и буква, когда программы нет.
static KEEP_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Запускает поток-добытчик. `dir` — папка для иконок, переживающих перезапуск;
/// `notify` зовётся из потока каждый раз, когда в кэше появилась очередная
/// пачка, — по этому сигналу UI перечитывает кэш.
pub fn init(dir: Option<PathBuf>, notify: impl Fn() + Send + 'static) {
    let (tx, rx) = mpsc::channel::<Job>();
    if JOBS.set(Mutex::new(tx)).is_err() {
        return;
    }
    if let Some(dir) = dir {
        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = KEEP_DIR.set(dir);
        }
    }
    let worker = move || {
        prune();
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
                    // Путь, по которому иконка нашлась: по нему же её кладут на
                    // диск, чтобы следующий запуск обошёлся без поиска.
                    let mut source = None;
                    let mut bits = if job.path.is_empty() {
                        None
                    } else {
                        extract(&job.path, job.size).inspect(|_| source = Some(job.path.clone()))
                    };
                    if bits.is_none() && !job.name.is_empty() {
                        let table = running.get_or_insert_with(running_paths);
                        if let Some(path) = table.get(&job.name.to_lowercase()) {
                            bits = extract(path, job.size).inspect(|_| source = Some(path.clone()));
                        }
                    }
                    if job.keep {
                        match &source {
                            Some(path) => keep(&job.name, path),
                            // Программы нет ни на своём месте, ни среди живых:
                            // остаётся то, что сохранено с прошлого раза.
                            None => bits = recall(&job.name, job.size),
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
    request(name, path, size, false)
}

/// То же для строки раздельного туннеля: её иконка переживает перезапуск —
/// добытая однажды, она остаётся на диске и приходит оттуда, когда программы
/// нет среди запущенных.
pub fn get_rule(name: &str, path: &str, size: u32) -> Option<slint::Image> {
    request(name, path, size, true)
}

/// Забыть, что иконку уже искали и не нашли. Отрицательный ответ кэшируется
/// навсегда — иначе список из сотни процессов ходил бы на диск за каждой
/// перерисовкой, — но для списка программ это значит «буква до конца сеанса»
/// у всего, что не было запущено в момент старта. Заход на страницу снимает
/// приговор: пока пользователь читал другую вкладку, программу могли открыть.
pub fn forget_missing() {
    let Ok(mut store) = STORE.lock() else { return };
    store.done.retain(|_, bits| bits.is_some());
    let known: HashSet<String> = store.done.keys().cloned().collect();
    // Ключи, ещё висящие в очереди, тоже уходят: заявка вернётся второй раз и
    // просто перезапишет тот же ответ.
    store.queued.retain(|key| known.contains(key));
}

fn request(name: &str, path: &str, size: u32, keep: bool) -> Option<slint::Image> {
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
        let job = Job { key, name: name.into(), path: path.into(), size, keep };
        let _ = jobs.lock().map(|jobs| jobs.send(job));
    }
    None
}

fn to_image(bits: &[u8], size: u32) -> slint::Image {
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(size, size);
    buffer.make_mut_bytes().copy_from_slice(bits);
    slint::Image::from_rgba8_premultiplied(buffer)
}

// ----------------------------------------------------- иконки, лежащие на диске

/// Подпись файла записи, её версия и длина заголовка: подпись, версия, сторона
/// снимка (u16) и длина пути (u16). Дальше идут сам путь и пиксели.
const KEEP_MAGIC: [u8; 4] = *b"AVIC";
const KEEP_VERSION: u8 = 1;
const KEEP_HEAD: usize = 9;

/// Файл записи для имени программы. Имя приводится к нижнему регистру и
/// чистится от всего, чему в имени файла не место; хвост из хэша разводит
/// программы, у которых после чистки остаётся одно и то же имя.
fn entry(name: &str) -> Option<PathBuf> {
    let dir = KEEP_DIR.get()?;
    if name.is_empty() {
        return None;
    }
    let lower = name.to_lowercase();
    let safe: String = lower
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // FNV-1a: хэш здесь только разводит имена, стойкость ни при чём.
    let tag = lower
        .bytes()
        .fold(0x811c_9dc5_u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    Some(dir.join(format!("{safe}-{tag:08x}.icon")))
}

/// Сохранённая запись: путь, сторона снимка и его пиксели.
fn saved(name: &str) -> Option<(String, u32, Vec<u8>)> {
    decode(&std::fs::read(entry(name)?).ok()?)
}

/// Разбор записи. `None` — файл не наш, от другой версии или недописан;
/// разбирать такой нельзя: обрезанный снимок ушёл бы в буфер картинки.
fn decode(blob: &[u8]) -> Option<(String, u32, Vec<u8>)> {
    if blob.len() < KEEP_HEAD || blob[..4] != KEEP_MAGIC || blob[4] != KEEP_VERSION {
        return None;
    }
    let side = u16::from_le_bytes([blob[5], blob[6]]) as u32;
    let path_len = u16::from_le_bytes([blob[7], blob[8]]) as usize;
    let pixels = KEEP_HEAD + path_len;
    // Сторона считается в u64 и с потолком: файл мог побиться, а квадрат
    // шестнадцатибитного числа из u32 уже вываливается.
    if side == 0 || side > 1024 || blob.len() as u64 != pixels as u64 + side as u64 * side as u64 * 4
    {
        return None;
    }
    let path = String::from_utf8(blob[KEEP_HEAD..pixels].to_vec()).ok()?;
    Some((path, side, blob[pixels..].to_vec()))
}

/// Сборка записи: подпись, версия, сторона снимка, длина пути — и следом сам
/// путь с пикселями.
fn encode(path: &str, side: u32, bits: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(KEEP_HEAD + path.len() + bits.len());
    blob.extend_from_slice(&KEEP_MAGIC);
    blob.push(KEEP_VERSION);
    blob.extend_from_slice(&(side as u16).to_le_bytes());
    blob.extend_from_slice(&(path.len() as u16).to_le_bytes());
    blob.extend_from_slice(path.as_bytes());
    blob.extend_from_slice(bits);
    blob
}

/// Оставить иконку программы на диске: путь, по которому она взялась, и снимок
/// на случай, если по этому пути её больше не окажется. Перезапись — только
/// когда путь сменился: обычно файл уже лежит, и трогать его незачем.
fn keep(name: &str, path: &str) {
    let Some(file) = entry(name) else { return };
    if path.len() > u16::MAX as usize {
        return;
    }
    if saved(name).is_some_and(|(old, _, _)| old.eq_ignore_ascii_case(path)) {
        return;
    }
    let Some(bits) = extract(path, KEEP_SIDE) else { return };
    // Через временный файл: оборванная запись оставила бы обрезанную картинку,
    // а следующий запуск принял бы её за настоящую.
    let tmp = file.with_extension("tmp");
    if std::fs::write(&tmp, encode(path, KEEP_SIDE, &bits)).is_ok()
        && std::fs::rename(&tmp, &file).is_err()
    {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Иконка из сохранённой записи. Сначала — по запомненному пути: программа
/// может быть просто не запущена, и тогда картинка возьмётся из её файла в
/// нужном размере. Не вышло (снесли, обновление увело в другую папку) — в дело
/// идёт снимок; он крупнее строки, и его достаточно усреднить.
fn recall(name: &str, size: u32) -> Option<Vec<u8>> {
    let (path, side, bits) = saved(name)?;
    if let Some(bits) = extract(&path, size) {
        return Some(bits);
    }
    match side.cmp(&size) {
        std::cmp::Ordering::Equal => Some(bits),
        std::cmp::Ordering::Greater => Some(shrink(&bits, side, side, size)),
        // Строка крупнее снимка — такое бывает разве что на экране с
        // трёхкратным масштабом. Растянутая картинка выглядит хуже буквы.
        std::cmp::Ordering::Less => None,
    }
}

/// Записи программ, вычеркнутых из списка, никто не убирает — их выносит эта
/// уборка, когда файлов в папке становится больше, чем разумно держать.
fn prune() {
    let Some(dir) = KEEP_DIR.get() else { return };
    let Ok(dir) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = dir
        .flatten()
        .filter_map(|item| {
            let meta = item.metadata().ok()?;
            meta.is_file().then_some(())?;
            Some((meta.modified().ok()?, item.path()))
        })
        .collect();
    if files.len() <= KEEP_LIMIT {
        return;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, file) in &files[..files.len() - KEEP_LIMIT] {
        let _ = std::fs::remove_file(file);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(side: u32) -> Vec<u8> {
        encode(r"C:\Program Files\App\app.exe", side, &vec![7u8; (side * side * 4) as usize])
    }

    #[test]
    fn record_round_trips() {
        let (path, side, bits) = decode(&blob(KEEP_SIDE)).unwrap();
        assert_eq!(path, r"C:\Program Files\App\app.exe");
        assert_eq!(side, KEEP_SIDE);
        assert_eq!(bits.len(), (KEEP_SIDE * KEEP_SIDE * 4) as usize);
    }

    /// Недописанный файл — это оборванная запись, а не иконка: разобрав её,
    /// строка получила бы наполовину пустой квадрат.
    #[test]
    fn truncated_record_is_refused() {
        let full = blob(KEEP_SIDE);
        assert!(decode(&full[..full.len() - 1]).is_none());
        assert!(decode(&full[..4]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn foreign_record_is_refused() {
        let mut wrong_magic = blob(KEEP_SIDE);
        wrong_magic[0] = b'X';
        assert!(decode(&wrong_magic).is_none());

        let mut wrong_version = blob(KEEP_SIDE);
        wrong_version[4] = KEEP_VERSION + 1;
        assert!(decode(&wrong_version).is_none());
    }

    /// Сторона из побитого заголовка не должна ни пройти проверку, ни
    /// переполнить счёт пикселей.
    #[test]
    fn absurd_side_is_refused() {
        let mut huge = blob(KEEP_SIDE);
        huge[5..7].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(decode(&huge).is_none());

        let mut zero = blob(KEEP_SIDE);
        zero[5..7].copy_from_slice(&0u16.to_le_bytes());
        assert!(decode(&zero).is_none());
    }

    /// Снимок крупнее строки усредняется до её размера — ровно теми пикселями,
    /// которыми строка и будет нарисована.
    #[test]
    fn snapshot_shrinks_to_the_row() {
        let src = vec![64u8; (KEEP_SIDE * KEEP_SIDE * 4) as usize];
        let out = shrink(&src, KEEP_SIDE, KEEP_SIDE, 30);
        assert_eq!(out.len(), 30 * 30 * 4);
        assert!(out.iter().all(|px| *px == 64));
    }
}
