//! Сервер туннеля. Принимает h2c от фронта (Caddy или nginx на 443 с
//! настоящим сайтом и сертификатом), проверяет жетон и выпускает поток в сеть.
//! TLS и сайт — забота фронта: так отпечаток сервера — отпечаток обычного
//! веб-сервера, а не самодельного.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::addr::{Addr, Host};
use crate::codec::{KIND_DATA, KIND_HEADER, MAX_RECORD_DATA};
use crate::crypto::{now, Token, UserKey, MAX_SKEW, NONCE_LEN};
use crate::ru::{is_ru_domain, CidrSet};
use crate::stream::{h2_error, RecvHalf, SendHalf, Source, VeilStream};
use crate::subs::{self, SubConfig};
use crate::{CMD_TCP, CMD_UDP, COOKIE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(120);
const STATS_EVERY: Duration = Duration::from_secs(600);
const RELOAD_EVERY: Duration = Duration::from_secs(30);
/// Как часто сверять выданный Veil с панелью: отключённых снимать.
const SUBS_CHECK_EVERY: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Deserialize)]
pub struct UserConf {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Куда фронт шлёт h2c. Снаружи этот порт виден быть не должен.
    pub listen: String,
    /// Путь туннеля, тот же в ссылке клиента и в конфиге фронта.
    pub path: String,
    pub users: Vec<UserConf>,
    /// Пускать ли в loopback и частные сети сервера (панель, база). Нет.
    pub allow_private: bool,
    /// Писать в журнал каждый поток: пользователь и цель.
    pub access_log: bool,
    /// Не выпускать наружу российские домены и адреса: российские платформы
    /// обязаны выявлять VPN и сдают IP сервера (см. `ru.rs`). Включено.
    pub block_ru: bool,
    /// Список сетей РФ, по CIDR в строке. Нет файла — режем только по доменам.
    pub ru_cidr_file: String,
    /// Подписки 3x-ui с Veil внутри (`subs.rs`). Нет раздела — нет и подписок.
    pub subscription: Option<SubConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".to_string(),
            path: "/".to_string(),
            users: Vec::new(),
            allow_private: false,
            access_log: false,
            block_ru: true,
            ru_cidr_file: "/etc/veil/ru-cidr.txt".to_string(),
            subscription: None,
        }
    }
}

impl ServerConfig {
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: ServerConfig = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?;
        if cfg.users.is_empty() && cfg.subscription.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "в конфиге нет ни одного пользователя"));
        }
        if let Some(sub) = &cfg.subscription {
            if sub.secret.len() < 16 || sub.host.is_empty() || !sub.prefix.starts_with('/') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "subscription: нужны secret (от 16 символов), host и prefix с /",
                ));
            }
        }
        if !cfg.path.starts_with('/') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "path должен начинаться с /"));
        }
        Ok(cfg)
    }
}

#[derive(Default)]
struct Stats {
    streams: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    /// Отрезанные российские адреса: у клиента выключено «Россия напрямую».
    ru_refused: AtomicU64,
}

struct User {
    name: String,
    key: UserKey,
    stats: Arc<Stats>,
}

struct State {
    cfg: ServerConfig,
    users: Vec<User>,
    ru_ips: Arc<CidrSet>,
}

/// Почему цель не выпускаем.
enum Refused {
    Io(io::Error),
    Private,
    Russian,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Io(e) => write!(f, "{e}"),
            Refused::Private => f.write_str("адрес в частной сети, закрыт"),
            Refused::Russian => f.write_str("российский адрес, закрыт"),
        }
    }
}

impl From<io::Error> for Refused {
    fn from(e: io::Error) -> Self {
        Refused::Io(e)
    }
}

pub struct Server {
    state: RwLock<Arc<State>>,
    /// Счётчики переживают перечитывание конфига.
    stats: Mutex<HashMap<String, Arc<Stats>>>,
    /// Увиденные nonce и время жетона: повтор перехваченного запроса не пройдёт.
    replay: Mutex<HashMap<[u8; NONCE_LEN], u64>>,
    /// subId из 3x-ui, которым уже выдан Veil.
    subs: Mutex<BTreeSet<String>>,
    config_path: Option<PathBuf>,
}

macro_rules! log {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Адреса назначения: сперва IPv4, IPv6 — запасным. glibc ставит IPv6 первым, и
/// весь трафик выходил бы с одного постоянного IPv6 сервера, который Google за
/// недели с российскими клиентами записал не в Нидерланды (YouTube отвечает UA,
/// вход в аккаунт — «Москва»). IPv4 у сервера свежий и числится по месту.
fn ipv4_first(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = addrs.into_iter().collect();
    addrs.sort_by_key(SocketAddr::is_ipv6);
    addrs
}

/// Один сокет на обе семьи: [::] без IPV6_V6ONLY (на Windows он включён по
/// умолчанию) принимает и IPv4 в обёртке. Без IPv6 на хосте — только IPv4.
fn udp_socket() -> io::Result<(UdpSocket, bool)> {
    use socket2::{Domain, Socket, Type};
    let dual = Socket::new(Domain::IPV6, Type::DGRAM, None).and_then(|s| {
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
        Ok(s)
    });
    let (socket, dual) = match dual {
        Ok(s) => (s, true),
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
            s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
            (s, false)
        }
    };
    socket.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(socket.into())?, dual))
}

fn load_ru_ips(cfg: &ServerConfig) -> CidrSet {
    if !cfg.block_ru || cfg.ru_cidr_file.is_empty() {
        return CidrSet::default();
    }
    match std::fs::read_to_string(&cfg.ru_cidr_file) {
        Ok(text) => {
            let (set, bad) = CidrSet::parse(&text);
            if bad > 0 {
                log!("{}: непонятных строк {bad}, пропущены", cfg.ru_cidr_file);
            }
            set
        }
        Err(e) => {
            log!("нет списка сетей РФ ({}: {e}) — российское режу только по доменам", cfg.ru_cidr_file);
            CidrSet::default()
        }
    }
}

/// Заголовок `Date`, как у любого веб-сервера: `Mon, 02 Nov 2026 17:49:31 GMT`.
fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Гражданская дата из дней от 1970-01-01 (алгоритм Говарда Хиннанта).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn mb(bytes: u64) -> String {
    format!("{:.1} МБ", bytes as f64 / 1_048_576.0)
}

impl Server {
    pub fn new(cfg: ServerConfig, config_path: Option<PathBuf>) -> Arc<Self> {
        let server = Arc::new(Self {
            state: RwLock::new(Arc::new(State {
                cfg: ServerConfig::default(),
                users: Vec::new(),
                ru_ips: Arc::new(CidrSet::default()),
            })),
            stats: Mutex::new(HashMap::new()),
            replay: Mutex::new(HashMap::new()),
            subs: Mutex::new(cfg.subscription.as_ref().map(|s| subs::load_known(&s.state_file)).unwrap_or_default()),
            config_path,
        });
        server.apply(cfg);
        server
    }

    fn apply(&self, cfg: ServerConfig) {
        let ru_ips = Arc::new(load_ru_ips(&cfg));
        let mut stats = self.stats.lock().unwrap();
        let mut users: Vec<User> = cfg
            .users
            .iter()
            .map(|u| User {
                name: u.name.clone(),
                key: UserKey::new(&u.password),
                stats: stats.entry(u.name.clone()).or_default().clone(),
            })
            .collect();
        if let Some(sub) = &cfg.subscription {
            for id in self.subs.lock().unwrap().iter() {
                let name = format!("sub:{id}");
                users.push(User {
                    key: UserKey::new(&subs::password(&sub.secret, id)),
                    stats: stats.entry(name.clone()).or_default().clone(),
                    name,
                });
            }
        }
        *self.state.write().unwrap() = Arc::new(State { cfg, users, ru_ips });
    }

    fn state(&self) -> Arc<State> {
        self.state.read().unwrap().clone()
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let state = self.state();
        let listener = TcpListener::bind(&state.cfg.listen).await?;
        log!(
            "veil-server {} слушает {} (h2c), путь {}, пользователей {}",
            env!("CARGO_PKG_VERSION"),
            state.cfg.listen,
            state.cfg.path,
            state.users.len()
        );
        if let Ok(addr) = listener.local_addr() {
            if !addr.ip().is_loopback() {
                log!("внимание: {addr} не loopback — закройте порт снаружи, иначе h2c без сайта виден пробам");
            }
        }
        tokio::spawn(self.clone().housekeeping());
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    // Кончились дескрипторы и подобное: не падаем, ждём.
                    log!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_conn(tcp, peer).await {
                    if e.kind() != io::ErrorKind::ConnectionReset {
                        log!("соединение от {peer}: {e}");
                    }
                }
            });
        }
    }

    /// Перечитать конфиг при изменении, раз в 10 минут — сводка по пользователям.
    async fn housekeeping(self: Arc<Self>) {
        let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let cidr_mtime = |this: &Self| mtime(Path::new(&this.state().cfg.ru_cidr_file));
        let mut seen = self.config_path.as_deref().and_then(mtime);
        let mut seen_cidr = cidr_mtime(&self);
        let mut last_stats = SystemTime::now();
        let mut last_subs_check = SystemTime::now();
        loop {
            tokio::time::sleep(RELOAD_EVERY).await;
            if last_subs_check.elapsed().unwrap_or_default() >= SUBS_CHECK_EVERY {
                last_subs_check = SystemTime::now();
                self.check_subs().await;
            }
            if cidr_mtime(&self) != seen_cidr {
                seen_cidr = cidr_mtime(&self);
                self.apply(self.state().cfg.clone());
                log!("список сетей РФ перечитан");
            }
            if let Some(path) = &self.config_path {
                let current = mtime(path);
                if current != seen {
                    seen = current;
                    match ServerConfig::load(path) {
                        Ok(cfg) => {
                            if cfg.listen != self.state().cfg.listen {
                                log!("listen изменился — вступит в силу после перезапуска");
                            }
                            let n = cfg.users.len();
                            self.apply(cfg);
                            log!("конфиг перечитан, пользователей {n}");
                        }
                        Err(e) => log!("конфиг не перечитан, работаю со старым: {e}"),
                    }
                }
            }
            {
                let horizon = now().saturating_sub(2 * MAX_SKEW);
                self.replay.lock().unwrap().retain(|_, ts| *ts >= horizon);
            }
            if last_stats.elapsed().unwrap_or_default() >= STATS_EVERY {
                last_stats = SystemTime::now();
                for (name, s) in self.stats.lock().unwrap().iter() {
                    let streams = s.streams.swap(0, Ordering::Relaxed);
                    let up = s.up.swap(0, Ordering::Relaxed);
                    let down = s.down.swap(0, Ordering::Relaxed);
                    let ru = s.ru_refused.swap(0, Ordering::Relaxed);
                    if streams > 0 {
                        let ru = if ru > 0 { format!(", отрезано российских {ru}") } else { String::new() };
                        log!("за 10 мин {name}: потоков {streams}, ↑ {}, ↓ {}{ru}", mb(up), mb(down));
                    }
                }
            }
        }
    }

    async fn serve_conn(self: Arc<Self>, tcp: TcpStream, peer: SocketAddr) -> io::Result<()> {
        tcp.set_nodelay(true)?;
        // Фронт обязан говорить h2c с предисловием. HTTP/1.1 здесь значит
        // ошибку в его конфиге — скажем об этом прямо.
        let mut head = [0u8; 3];
        let n = timeout(Duration::from_secs(10), tcp.peek(&mut head)).await.map_err(|_| io::ErrorKind::TimedOut)??;
        // Фронт держит запас соединений и закрывает лишние, не написав ни байта.
        if n == 0 {
            return Ok(());
        }
        if head[..n] != b"PRI"[..n] {
            log!(
                "{peer} прислал не h2c ({:?}…): в Caddy нужно `transport http {{ versions h2c }}`, в nginx — grpc_pass",
                String::from_utf8_lossy(&head[..n])
            );
            return Ok(());
        }
        let mut conn = h2::server::Builder::new()
            .initial_window_size(4 * 1024 * 1024)
            .initial_connection_window_size(16 * 1024 * 1024)
            .max_concurrent_streams(1024)
            .handshake::<_, Bytes>(tcp)
            .await
            .map_err(h2_error)?;
        while let Some(next) = conn.accept().await {
            let (request, respond) = next.map_err(h2_error)?;
            let this = self.clone();
            tokio::spawn(async move { this.serve_stream(request, respond).await });
        }
        Ok(())
    }

    fn auth(&self, state: &State, headers: &HeaderMap) -> Result<(usize, [u8; NONCE_LEN]), &'static str> {
        let token = headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
            .ok_or("нет жетона")?;
        let token = Token::parse(token).ok_or("жетон испорчен")?;
        if !token.fresh(now()) {
            return Err("жетон устарел: часы клиента расходятся с сервером больше чем на 5 минут");
        }
        let index = state.users.iter().position(|u| u.key.verify(&token)).ok_or("неизвестный пароль")?;
        let mut replay = self.replay.lock().unwrap();
        if replay.insert(token.nonce, token.ts).is_some() {
            return Err("повтор жетона");
        }
        Ok((index, token.nonce))
    }

    /// Выданный Veil сверить с панелью: чью подписку 3x-ui больше не отдаёт
    /// (клиент отключён, удалён, кончился срок), тому доступ снять. Сбой связи
    /// с панелью ничего не снимает.
    pub async fn check_subs(&self) {
        let Some(sub) = self.state().cfg.subscription.clone() else { return };
        let known: Vec<String> = self.subs.lock().unwrap().iter().cloned().collect();
        let mut revoked = Vec::new();
        for id in known {
            match subs::fetch(&sub, &id, None).await {
                Ok(f) if !f.alive() => revoked.push(id),
                Ok(_) => {}
                Err(e) => {
                    log!("сверка подписок прервана: {e}");
                    return;
                }
            }
        }
        if revoked.is_empty() {
            return;
        }
        {
            let mut set = self.subs.lock().unwrap();
            for id in &revoked {
                set.remove(id);
            }
            if let Err(e) = subs::save_known(&sub.state_file, &set) {
                log!("{}: {e}", sub.state_file);
            }
        }
        for id in &revoked {
            log!("sub:{id}: подписка в панели больше не выдаётся — доступ к Veil снят");
        }
        self.apply(self.state().cfg.clone());
    }

    /// `GET {prefix}{subId}`: подписка панели с Veil в конце.
    async fn serve_subscription(&self, sub: &SubConfig, state: &State, request: &Request<RecvStream>, mut respond: SendResponse<Bytes>) {
        let id = request.uri().path().strip_prefix(sub.prefix.as_str()).unwrap_or("").trim_end_matches('/');
        let not_found = |respond: &mut SendResponse<Bytes>| {
            let response = Response::builder().status(StatusCode::NOT_FOUND).header("date", http_date(now())).body(()).unwrap();
            let _ = respond.send_response(response, true);
        };
        if !subs::valid_sub_id(id) {
            return not_found(&mut respond);
        }
        let agent = request.headers().get(http::header::USER_AGENT).and_then(|v| v.to_str().ok());
        let fetched = match subs::fetch(sub, id, agent).await {
            Ok(f) => f,
            Err(e) => {
                log!("подписка {id}: {e}");
                let response =
                    Response::builder().status(StatusCode::BAD_GATEWAY).header("date", http_date(now())).body(()).unwrap();
                let _ = respond.send_response(response, true);
                return;
            }
        };
        if !fetched.alive() {
            let removed = self.subs.lock().unwrap().remove(id);
            if removed {
                let _ = subs::save_known(&sub.state_file, &self.subs.lock().unwrap());
                log!("sub:{id}: подписка в панели больше не выдаётся — доступ к Veil снят");
                self.apply(state.cfg.clone());
            }
            return not_found(&mut respond);
        }
        let body = if sub.wants_veil(agent) {
            let added = self.subs.lock().unwrap().insert(id.to_string());
            if added {
                let _ = subs::save_known(&sub.state_file, &self.subs.lock().unwrap());
                log!("sub:{id}: Veil выдан");
                self.apply(state.cfg.clone());
            }
            subs::merge(&fetched.body, &subs::link(sub, &state.cfg.path, id))
        } else {
            fetched.body.clone()
        };
        let mut response = Response::builder().status(StatusCode::OK).header("date", http_date(now()));
        for (name, value) in subs::passed_headers(&fetched) {
            response = response.header(name.as_str(), value.as_str());
        }
        let response = response.header("content-length", body.len()).body(()).unwrap();
        let Ok(mut send) = respond.send_response(response, false) else { return };
        let _ = send.send_data(Bytes::from(body), true);
    }

    async fn serve_stream(self: Arc<Self>, request: Request<RecvStream>, mut respond: SendResponse<Bytes>) {
        let state = self.state();
        if let Some(sub) = &state.cfg.subscription {
            if request.method() == Method::GET && request.uri().path().starts_with(sub.prefix.as_str()) {
                return self.serve_subscription(sub, &state, &request, respond).await;
            }
        }
        let on_path = request.uri().path() == state.cfg.path;
        let authed = if on_path && request.method() == Method::POST {
            self.auth(&state, request.headers())
        } else {
            Err("не тот метод или путь")
        };
        let (index, nonce) = match authed {
            Ok(ok) => ok,
            Err(reason) => {
                if on_path {
                    let from = request
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("?")
                        .to_string();
                    log!("отказ {from}: {reason}");
                }
                // Как у сайта на неизвестный адрес: пустой 404 с датой.
                let response =
                    Response::builder().status(StatusCode::NOT_FOUND).header("date", http_date(now())).body(()).unwrap();
                let _ = respond.send_response(response, true);
                return;
            }
        };
        let user = &state.users[index];
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("date", http_date(now()))
            .header("content-type", "application/octet-stream")
            .header("cache-control", "no-store")
            .body(())
            .unwrap();
        let Ok(send) = respond.send_response(response, false) else { return };
        let (up, down) = user.key.stream_keys(&nonce);
        let mut rx = RecvHalf::new(Source::Body(request.into_body()), &up);
        let mut tx = SendHalf::new(send, &down);

        let header = match timeout(Duration::from_secs(30), rx.record()).await {
            Ok(Ok(Some((KIND_HEADER, header)))) if header.len() > 1 => header,
            _ => {
                tx.reset();
                return;
            }
        };
        let Some((addr, _)) = Addr::read(&header[1..]) else {
            tx.reset();
            return;
        };
        user.stats.streams.fetch_add(1, Ordering::Relaxed);
        if state.cfg.block_ru && matches!(&addr.host, Host::Domain(d) if is_ru_domain(d)) {
            Self::refuse_ru(user, &addr);
            tx.reset();
            return;
        }
        match header[0] {
            CMD_TCP => self.relay_tcp(&state, user, rx, tx, addr).await,
            CMD_UDP => self.relay_udp(&state, user, rx, tx).await,
            _ => tx.reset(),
        }
    }

    /// Первый отказ за 10 минут — в журнал сразу: по нему видно, у кого из
    /// друзей выключено «Россия напрямую». Остальные — числом в сводке.
    fn refuse_ru(user: &User, addr: &Addr) {
        if user.stats.ru_refused.fetch_add(1, Ordering::Relaxed) == 0 {
            log!(
                "{}: {addr} — российский адрес через туннель, отрезан. У клиента выключено «Россия напрямую»",
                user.name
            );
        }
    }

    fn check_ip(state: &State, ip: IpAddr) -> Result<(), Refused> {
        if !state.cfg.allow_private && !is_public(ip) {
            return Err(Refused::Private);
        }
        if state.cfg.block_ru && state.ru_ips.contains(ip) {
            return Err(Refused::Russian);
        }
        Ok(())
    }

    async fn resolve(state: &State, addr: &Addr) -> Result<Vec<SocketAddr>, Refused> {
        let all: Vec<SocketAddr> = match &addr.host {
            Host::Ip(ip) => vec![SocketAddr::new(*ip, addr.port)],
            Host::Domain(d) => ipv4_first(tokio::net::lookup_host((d.as_str(), addr.port)).await?),
        };
        let mut refused = None;
        let allowed: Vec<SocketAddr> = all
            .iter()
            .copied()
            .filter(|a| match Self::check_ip(state, a.ip()) {
                Ok(()) => true,
                Err(why) => {
                    refused = Some(why);
                    false
                }
            })
            .collect();
        if allowed.is_empty() {
            return Err(refused.unwrap_or_else(|| Refused::Io(io::ErrorKind::NotFound.into())));
        }
        Ok(allowed)
    }

    async fn connect(state: &State, addr: &Addr) -> Result<TcpStream, Refused> {
        let mut last = None;
        for target in Self::resolve(state, addr).await?.into_iter().take(4) {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last = Some(e),
                Err(_) => last = Some(io::ErrorKind::TimedOut.into()),
            }
        }
        Err(Refused::Io(last.unwrap_or_else(|| io::ErrorKind::NotFound.into())))
    }

    async fn relay_tcp(&self, state: &State, user: &User, rx: RecvHalf, mut tx: SendHalf, addr: Addr) {
        let mut target = match Self::connect(state, &addr).await {
            Ok(stream) => stream,
            Err(Refused::Russian) => {
                Self::refuse_ru(user, &addr);
                tx.reset();
                return;
            }
            Err(e) => {
                if state.cfg.access_log {
                    log!("{} tcp {addr}: {e}", user.name);
                }
                tx.reset();
                return;
            }
        };
        if state.cfg.access_log {
            log!("{} tcp {addr}", user.name);
        }
        let _ = target.set_nodelay(true);
        let mut veil = VeilStream::new(rx, tx);
        if let Ok((up, down)) = tokio::io::copy_bidirectional_with_sizes(&mut veil, &mut target, 64 * 1024, 64 * 1024).await {
            user.stats.up.fetch_add(up, Ordering::Relaxed);
            user.stats.down.fetch_add(down, Ordering::Relaxed);
        }
    }

    async fn relay_udp(&self, state: &State, user: &User, mut rx: RecvHalf, mut tx: SendHalf) {
        let (socket, dual) = match udp_socket() {
            Ok(pair) => pair,
            Err(_) => return tx.reset(),
        };
        if state.cfg.access_log {
            log!("{} udp", user.name);
        }
        let mut names: HashMap<String, IpAddr> = HashMap::new();
        let mut buf = vec![0u8; 65536];
        let (mut up, mut down) = (0u64, 0u64);
        loop {
            tokio::select! {
                record = rx.record() => {
                    let data = match record {
                        Ok(Some((KIND_DATA, data))) => data,
                        Ok(Some(_)) => continue,
                        _ => break,
                    };
                    let Some((addr, used)) = Addr::read(&data) else { continue };
                    if state.cfg.block_ru && matches!(&addr.host, Host::Domain(d) if is_ru_domain(d)) {
                        Self::refuse_ru(user, &addr);
                        continue;
                    }
                    let ip = match &addr.host {
                        Host::Ip(ip) => Some(*ip),
                        Host::Domain(d) => match names.get(d) {
                            Some(ip) => Some(*ip),
                            None => {
                                let found = match &addr.host {
                                    Host::Domain(d) => tokio::net::lookup_host((d.as_str(), addr.port))
                                        .await
                                        .ok()
                                        .and_then(|a| ipv4_first(a).first().copied())
                                        .map(|s| s.ip()),
                                    Host::Ip(ip) => Some(*ip),
                                };
                                if let Some(ip) = found {
                                    if names.len() > 256 { names.clear(); }
                                    names.insert(d.clone(), ip);
                                }
                                found
                            }
                        },
                    };
                    let Some(ip) = ip else { continue };
                    match Self::check_ip(state, ip) {
                        Ok(()) => {}
                        Err(Refused::Russian) => {
                            Self::refuse_ru(user, &addr);
                            continue;
                        }
                        Err(_) => continue,
                    }
                    let ip = match ip {
                        IpAddr::V4(v4) if dual => IpAddr::V6(v4.to_ipv6_mapped()),
                        IpAddr::V6(_) if !dual => continue,
                        other => other,
                    };
                    let payload = &data[used..];
                    if socket.send_to(payload, SocketAddr::new(ip, addr.port)).await.is_ok() {
                        up += payload.len() as u64;
                    }
                }
                got = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = got else { continue };
                    let mut frame = Vec::with_capacity(n + 19);
                    Addr::from_socket(from).write(&mut frame);
                    frame.extend_from_slice(&buf[..n]);
                    if frame.len() > MAX_RECORD_DATA {
                        continue;
                    }
                    if tx.send(KIND_DATA, &frame, true).await.is_err() {
                        break;
                    }
                    down += n as u64;
                }
                _ = tokio::time::sleep(UDP_IDLE) => break,
            }
        }
        let _ = tx.finish();
        user.stats.up.fetch_add(up, Ordering::Relaxed);
        user.stats.down.fetch_add(down, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_793_641_771), "Mon, 02 Nov 2026 17:49:31 GMT");
        assert_eq!(http_date(1_835_438_400), "Tue, 29 Feb 2028 12:00:00 GMT");
    }

    #[test]
    fn private_ranges_closed() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2a00:1450::1", "::ffff:8.8.8.8"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ipv4_goes_first_and_order_within_a_family_holds() {
        let got = ipv4_first(
            ["[2a00:1450::1]:443", "142.250.1.1:443", "[2a00:1450::2]:443", "142.250.1.2:443"]
                .map(|a| a.parse::<SocketAddr>().unwrap()),
        );
        let got: Vec<String> = got.iter().map(ToString::to_string).collect();
        assert_eq!(got, ["142.250.1.1:443", "142.250.1.2:443", "[2a00:1450::1]:443", "[2a00:1450::2]:443"]);
    }
}
