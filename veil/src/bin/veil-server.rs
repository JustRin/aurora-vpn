//! veil-server: серверная сторона Veil.
//!
//! ```text
//! veil-server run -c /etc/veil/config.json
//! veil-server init --host example.com            новый конфиг в stdout
//! veil-server init --host example.com --xui      с подписками 3x-ui (subs.rs)
//! veil-server adduser -c config.json --host example.com имя
//! veil-server link -c config.json --host example.com имя
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aura_veil::crypto::generate_password;
use aura_veil::server::{Server, ServerConfig};
use rand::Rng;
use serde_json::{json, Value};

const USAGE: &str = "veil-server run -c config.json
veil-server init --host ДОМЕН [--listen 127.0.0.1:8443] [--xui]
veil-server adduser -c config.json --host ДОМЕН [--port 443] ИМЯ
veil-server link -c config.json --host ДОМЕН [--port 443] ИМЯ";

struct Args {
    command: String,
    config: Option<PathBuf>,
    host: Option<String>,
    port: u16,
    listen: String,
    xui: bool,
    name: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut args = Args {
        command: String::new(),
        config: None,
        host: None,
        port: 443,
        listen: "127.0.0.1:8443".to_string(),
        xui: false,
        name: None,
    };
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| it.next().ok_or_else(|| format!("{flag}: нет значения"));
        match arg.as_str() {
            "-c" | "--config" => args.config = Some(PathBuf::from(value(&arg)?)),
            "--host" => args.host = Some(value(&arg)?),
            "--port" => args.port = value(&arg)?.parse().map_err(|_| "--port: не число")?,
            "--listen" => args.listen = value(&arg)?,
            "--xui" => args.xui = true,
            "-h" | "--help" => return Err(String::new()),
            _ if args.command.is_empty() => args.command = arg,
            _ if args.name.is_none() => args.name = Some(arg),
            other => return Err(format!("лишний аргумент {other}")),
        }
    }
    if args.command.is_empty() {
        args.command = "run".to_string();
    }
    Ok(args)
}

fn percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn link(cfg: &ServerConfig, host: &str, port: u16, name: &str) -> Result<String, String> {
    let user = cfg.users.iter().find(|u| u.name == name).ok_or_else(|| format!("нет пользователя {name}"))?;
    Ok(format!(
        "veil://{}@{host}:{port}?path={}&sni={host}&fp=chrome#{}",
        user.password,
        percent(&cfg.path),
        percent(name)
    ))
}

/// Путь туннеля похож на API обычного сайта и у каждого сервера свой.
fn random_path() -> String {
    const WORDS: [&str; 6] = ["sync", "events", "collect", "updates", "feed", "stream"];
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let id: String = (0..10).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect();
    format!("/api/v1/{}/{id}", WORDS[rng.gen_range(0..WORDS.len())])
}

fn need<'a, T>(value: &'a Option<T>, what: &str) -> Result<&'a T, String> {
    value.as_ref().ok_or_else(|| format!("нужен {what}\n\n{USAGE}"))
}

fn add_user(path: &Path, name: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut doc: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let users = doc["users"].as_array_mut().ok_or("в конфиге нет массива users")?;
    if users.iter().any(|u| u["name"] == name) {
        return Err(format!("пользователь {name} уже есть"));
    }
    users.push(json!({ "name": name, "password": generate_password() }));
    let out = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    // Через временный файл: сервер перечитывает конфиг на ходу и не должен
    // поймать его наполовину записанным.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, out + "\n").map_err(|e| format!("{}: {e}", tmp.display()))?;
    // Права и владелец как у прежнего файла: в нём пароли, а служба читает
    // его от своего пользователя.
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = std::os::unix::fs::chown(&tmp, Some(meta.uid()), Some(meta.gid()));
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}\n");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result: Result<(), String> = (|| match args.command.as_str() {
        "run" => {
            let path = need(&args.config, "-c config.json")?;
            let cfg = ServerConfig::load(path).map_err(|e| e.to_string())?;
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
            runtime.block_on(Server::new(cfg, Some(path.clone())).run()).map_err(|e| e.to_string())
        }
        "init" => {
            let host = need(&args.host, "--host")?;
            let mut doc = json!({
                "listen": args.listen,
                "path": random_path(),
                "allow_private": false,
                "access_log": false,
                "block_ru": true,
                "ru_cidr_file": "/etc/veil/ru-cidr.txt",
                "users": [{ "name": "admin", "password": generate_password() }],
            });
            if args.xui {
                // Подписка 3x-ui по HTTP на localhost; к TLS-подписке панели
                // мостом служит Caddy (deploy/install.sh --xui).
                doc["subscription"] = json!({
                    "upstream": "http://127.0.0.1:2097/subs/",
                    "prefix": "/subs/",
                    "secret": generate_password(),
                    "host": host,
                    "port": 443,
                    "remark": "Veil",
                    "state_file": "/var/lib/veil/subs.json",
                });
            }
            println!("{}", serde_json::to_string_pretty(&doc).unwrap());
            eprintln!("готово: сохраните в config.json, ссылку даст `veil-server link -c config.json --host {host} admin`");
            Ok(())
        }
        "adduser" | "link" => {
            let path = need(&args.config, "-c config.json")?;
            let host = need(&args.host, "--host")?;
            let name = need(&args.name, "имя пользователя")?;
            if args.command == "adduser" {
                add_user(path, name)?;
            }
            let cfg = ServerConfig::load(path).map_err(|e| e.to_string())?;
            println!("{}", link(&cfg, host, args.port, name)?);
            Ok(())
        }
        other => Err(format!("неизвестная команда {other}\n\n{USAGE}")),
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
