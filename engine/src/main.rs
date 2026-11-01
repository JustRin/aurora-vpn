//! Командная строка движка: для стенда и ручной проверки. Совместима с sing-box
//! настолько, насколько этим пользуются тесты: `run -c … -D …`, `check -c …`, `version`.

use std::path::PathBuf;
use std::process::ExitCode;

use aura_engine::{check, rule_set_matches, start, Options, VERSION_LINE};

fn arg_value(args: &[String], names: &[&str]) -> Option<String> {
    let at = args.iter().position(|a| names.contains(&a.as_str()))?;
    args.get(at + 1).cloned()
}

fn usage() -> ExitCode {
    eprintln!("использование: aura-engine run -c config.json [-D каталог] | check -c config.json | version");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "version" => {
            println!("{VERSION_LINE}\n\nEnvironment: rust {}/{}", std::env::consts::OS, std::env::consts::ARCH);
            ExitCode::SUCCESS
        }
        "check" => {
            let Some(path) = arg_value(&args, &["-c", "--config"]) else {
                return usage();
            };
            match check(&PathBuf::from(path)) {
                Ok(skipped) => {
                    for (tag, reason) in skipped {
                        eprintln!("{tag}: {reason}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        // Проверка набора правил: «aura-engine match файл.srs имя-или-адрес…».
        "match" => {
            let Some((file, queries)) = args[1..].split_first() else {
                return usage();
            };
            match rule_set_matches(std::path::Path::new(file), queries) {
                Ok(hits) => {
                    for (query, hit) in queries.iter().zip(hits) {
                        println!("{} {query}", u8::from(hit));
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        "run" => {
            let Some(path) = arg_value(&args, &["-c", "--config"]) else {
                return usage();
            };
            if let Some(dir) = arg_value(&args, &["-D", "--directory"]) {
                let _ = std::env::set_current_dir(dir);
            }
            match start(Options { config: PathBuf::from(path), wintun: None, log: None }) {
                Ok(engine) => {
                    wait_for_exit();
                    engine.stop();
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("+0000 ERROR main: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}

fn wait_for_exit() {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return;
    };
    let _ = runtime.block_on(tokio::signal::ctrl_c());
}
