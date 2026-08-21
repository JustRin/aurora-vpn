/// Иконка приложения для окна и панели задач: PNG разбирается здесь, а в
/// бинарь попадают готовые пиксели.
///
/// Разметка умеет `@image-url`, но обе её раскладки не подходят. `EmbedFiles`
/// кладёт файл как есть и декодирует его на запуске — а значит тянет в бинарь
/// декодер PNG (фича `image-default-formats`, которой у slint по умолчанию
/// нет). `EmbedForSoftwareRenderer` декодирует на сборке, но заодно включает
/// проход `embed_glyphs`: шрифты растеризуются компилятором заранее, и текст
/// перестаёт идти через свой поправленный растеризатор (vendor/…/PATCH.md).
const ICON: &str = "../src-tauri/icons/128x128.png";

/// Иконка самого .exe. Проводник, панель задач и Alt-Tab берут её из ресурсов
/// исполняемого файла: класс окна winit заводит с `hIcon: 0`, своей иконки у
/// окна нет, и система спускается к иконке процесса.
const EXE_ICON: &str = "../src-tauri/icons/icon.ico";

fn main() {
    // Нужен на запуске, чтобы найти ядро рядом с exe: в дереве сборки sing-box
    // и xray лежат с суффиксом целевой тройки.
    println!(
        "cargo:rustc-env=TARGET_TRIPLE={}",
        std::env::var("TARGET").unwrap_or_default()
    );

    // Версия приложения живёт в package.json и больше нигде: по ней проверка
    // обновлений сравнивает себя с последним релизом на GitHub.
    const PACKAGE_JSON: &str = "../package.json";
    println!("cargo:rerun-if-changed={PACKAGE_JSON}");
    let manifest = std::fs::read_to_string(PACKAGE_JSON).expect("package.json");
    let version = manifest
        .split(r#""version""#)
        .nth(1)
        .and_then(|tail| tail.split('"').nth(1))
        .expect("version в package.json");
    println!("cargo:rustc-env=APP_VERSION={version}");

    slint_build::compile("ui/app.slint").expect("slint markup failed to compile");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    println!("cargo:rerun-if-changed={ICON}");
    let file = std::fs::File::open(ICON).unwrap_or_else(|e| panic!("{ICON}: {e}"));
    let mut reader = png::Decoder::new(std::io::BufReader::new(file))
        .read_info()
        .unwrap_or_else(|e| panic!("{ICON}: {e}"));
    let mut pixels = vec![0u8; reader.output_buffer_size().expect("икона слишком велика")];
    let info = reader
        .next_frame(&mut pixels)
        .unwrap_or_else(|e| panic!("{ICON}: {e}"));
    // Сторона зашита в main.rs (`app_icon`), формат — в `Image::from_rgba8`.
    assert_eq!(
        (info.width, info.height, info.color_type, info.bit_depth),
        (128, 128, png::ColorType::Rgba, png::BitDepth::Eight),
        "{ICON}: ожидались 128×128 RGBA8"
    );
    pixels.truncate(info.buffer_size());

    let rgba = out.join("app-icon.rgba");
    std::fs::write(&rgba, &pixels).unwrap_or_else(|e| panic!("{}: {e}", rgba.display()));

    embed_resources(&out, version);
}

/// Иконка и сведения о версии попадают в бинарь одним ресурсом: .rc собирает
/// rc.exe из Windows SDK, крейт лишь находит компилятор и подкладывает
/// результат линкеру.
///
/// Сведения о версии нужны не для галочки: в столбце «Имя» диспетчер задач
/// показывает FileDescription, и без ресурса ему остаётся имя файла.
fn embed_resources(out: &std::path::Path, version: &str) {
    println!("cargo:rerun-if-changed={EXE_ICON}");
    // .ico ложится рядом с .rc, и внутри разметки ресурса стоит одно имя
    // файла: rc.exe ищет его от папки самого .rc, а абсолютный путь пришлось
    // бы экранировать — строки в .rc устроены как в Си.
    let ico = out.join("app.ico");
    std::fs::copy(EXE_ICON, &ico).unwrap_or_else(|e| panic!("{EXE_ICON}: {e}"));

    // FILEVERSION требует ровно четырёх чисел, а версия у нас из трёх —
    // четвёртое добиваем нулём.
    let mut parts = version.split('.').map(|part| part.parse::<u16>().unwrap_or(0));
    let (major, minor, patch) = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );

    // Иконка под номером 1: проводник рисует группу с наименьшим
    // идентификатором. Строки ресурса намеренно только латиницей — rc.exe
    // читает .rc в кодировке ANSI, и кириллица приехала бы туда мусором.
    let rc = out.join("app.rc");
    let body = format!(
        r#"1 ICON "app.ico"

1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEOS 0x4L
FILETYPE 0x1L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "Aurora VPN"
            VALUE "FileDescription", "Aurora VPN"
            VALUE "FileVersion", "{version}"
            VALUE "InternalName", "aurora-vpn"
            VALUE "OriginalFilename", "aurora-vpn.exe"
            VALUE "ProductName", "Aurora VPN"
            VALUE "ProductVersion", "{version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );
    std::fs::write(&rc, body).unwrap_or_else(|e| panic!("{}: {e}", rc.display()));

    // Не optional: без rc.exe собрался бы внешне исправный .exe с чужой
    // иконкой и чужим именем, а заметить это можно только глазами.
    embed_resource::compile(&rc, embed_resource::NONE)
        .manifest_required()
        .expect("не удалось собрать ресурс с иконкой и версией");
}
