//! Балансировщик: решает, через какой узел идёт трафик.
//!
//! Живёт в приложении поверх Clash API, а не в `urltest` ядра, и вот почему.
//! У ядра один критерий — минимальная задержка последнего замера с допуском —
//! и никакого понятия «этот сервер только что умер»: после неудачного дозвона
//! оно ждёт следующего планового обхода, а обход у него один на всех, раз в
//! несколько минут. Отсюда знакомая по Hiddify картина: серверы с задержкой в
//! пределах шума меняются местами каждый обход, а упавший держит трафик до
//! конца интервала.
//!
//! Решения принимает [`Brain`] — автомат без сети: ему сообщают результаты
//! замеров, он говорит, что мерить дальше и когда переключаться. Дозванивается
//! до узлов и переключает селектор поводырь (`spawn_balancer` в командах).
//! Разделение ради тестов: сценарии «упал», «стал быстрее на грани допуска»,
//! «ожил и снова упал» проверяются без ядра, на модельном времени.
//!
//! Стратегии поверх общего механизма:
//! * `Failover` — выбранный сервер основной; ушёл — на лучший из живых, и
//!   обратно, когда основной подержится живым. Каждое следующее возвращение
//!   требует вдвое дольше: дёргающийся сервер так постепенно выпадает из игры.
//! * `Fastest` — переход только на тот, что быстрее нынешнего на допуск два
//!   обхода подряд; первый обход после подключения — сразу.
//! * `Rotate` — каждый обход следующий живой по списку.
//!
//! Общее для всех: текущий узел проверяется каждые 20 секунд, после осечки —
//! через пять; две осечки подряд — сервер мёртв, и переход немедленно, а не в
//! следующий обход. Кандидат, замер которого устарел, перед переходом
//! перепроверяется. Автоматический переход живых соединений не рвёт (селектор
//! собран с `interrupt_exist_connections: false`); рвутся только соединения
//! через мёртвый узел — им всё равно не жить.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::settings::Balancer;

/// Как часто проверять узел, через который идёт трафик.
pub const PROBE_EVERY: Duration = Duration::from_secs(20);
/// После осечки — перепроверка скорее: две осечки подряд должны находиться за
/// секунды, а не за минуту.
pub const RETRY_AFTER: Duration = Duration::from_secs(5);
/// Столько осечек подряд — узел мёртв.
pub const FAIL_LIMIT: u32 = 2;
/// «Самый быстрый»: сколько обходов подряд кандидат должен опережать текущий
/// узел на допуск, прежде чем на него перейдут.
pub const STREAK: u32 = 2;
/// «С резервом»: сколько удачных проверок подряд должен набрать основной,
/// чтобы на него вернуться. Удваивается с каждой его смертью.
pub const RECOVER_BASE: u32 = 3;
/// Узлов за один шаг обхода. Обход идёт кусками, чтобы между ними успевала
/// очередная проверка текущего узла: на сотне узлов сплошной обход длится до
/// минуты, и всё это время смерть текущего осталась бы незамеченной.
pub const CHUNK: usize = 8;
/// Сколько последних удачных замеров держим на узел: его задержка — медиана по
/// ним. Один замер через прокси гуляет на десятки миллисекунд.
const SAMPLES: usize = 3;
/// Замер не старше этого перед переходом не перепроверяется.
const FRESH: Duration = Duration::from_secs(30);
/// Дольше этого поводырю спать незачем: настройки могли смениться.
const IDLE_CAP: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub strategy: Balancer,
    /// Допуск «самого быстрого», мс.
    pub tolerance: u32,
    /// Период полного обхода.
    pub interval: Duration,
}

/// Что известно об узле.
#[derive(Debug, Clone, Default)]
struct Health {
    samples: VecDeque<u32>,
    /// Осечек подряд; обнуляется удачным замером.
    fails: u32,
    ok_at: Option<Instant>,
    probed_at: Option<Instant>,
}

impl Health {
    /// Последний замер удался, и есть по чему судить о задержке.
    fn alive(&self) -> bool {
        self.fails == 0 && !self.samples.is_empty()
    }

    /// Медиана последних замеров.
    fn delay(&self) -> Option<u32> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<u32> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }

    /// Последний удачный замер.
    fn latest(&self) -> Option<u32> {
        self.samples.back().copied()
    }
}

/// Почему переключаемся — для журнала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Первый обход после подключения: кандидат быстрее на `gain` мс.
    Initial { gain: u32 },
    /// Текущий узел не ответил `fails` раз подряд.
    Dead { fails: u32 },
    /// Кандидат быстрее на `gain` мс `STREAK` обходов подряд.
    Faster { gain: u32 },
    /// Основной снова отвечает.
    Recovered,
    /// Плановая ротация.
    Rotation,
}

/// Что поводырю делать дальше.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Нечего делать; вернуться не позже чем через столько.
    Idle(Duration),
    /// Измерить узлы (параллельно) и сообщить результаты через `report_batch`.
    Probe(Vec<String>),
    /// Переключить селектор с `from` на `to`; удалось — `commit`, нет — `abort`.
    Switch {
        from: String,
        to: String,
        reason: Reason,
    },
    /// Текущий узел мёртв, а живых кандидатов нет: остаёмся; сообщается раз.
    Stranded,
}

/// Начатый переход: кандидаты по убыванию предпочтения, голова — следующий к
/// проверке.
struct Pending {
    reason: Reason,
    queue: VecDeque<String>,
    since: Instant,
}

pub struct Brain {
    cfg: Config,
    primary: String,
    routed: String,
    /// Узлы, которые можно мерить и на которые можно переходить, в порядке
    /// списка. Сюда не попадают узлы, дозвон до которых способен уронить ядро
    /// (см. auto-группу в config.rs): такой узел бывает только основным — по
    /// воле пользователя — и пока трафик идёт мимо него, его не трогают.
    candidates: Vec<String>,
    health: HashMap<String, Health>,
    /// Остаток текущего обхода.
    sweep: VecDeque<String>,
    /// Последний выданный шаг был куском обхода.
    sweeping: bool,
    last_sweep: Option<Instant>,
    /// Завершённых обходов.
    sweeps: u32,
    /// Обход, по итогам которого уже принимали решение.
    judged: u32,
    /// Решений по обходам у этого автомата: первое — расстановка, дальше —
    /// поправки. Предшественнику не наследуется нарочно: новая стратегия
    /// или перезапуск ядра — повод расставиться заново.
    rounds: u32,
    /// «Самый быстрый»: кандидат и сколько обходов подряд он впереди.
    ahead: Option<(String, u32)>,
    /// «С резервом»: удачных проверок основного подряд, пока трафик на резерве.
    primary_ok: u32,
    /// «С резервом»: сколько раз основной умирал.
    primary_deaths: u32,
    pending: Option<Pending>,
    /// Обход, на котором сдались за неимением живых: до следующего не дёргаться.
    stranded_at: Option<u32>,
}

impl Brain {
    pub fn new(cfg: Config, primary: impl Into<String>, candidates: Vec<String>) -> Self {
        let primary = primary.into();
        Self {
            cfg,
            routed: primary.clone(),
            primary,
            candidates,
            health: HashMap::new(),
            sweep: VecDeque::new(),
            sweeping: false,
            last_sweep: None,
            sweeps: 0,
            judged: 0,
            rounds: 0,
            ahead: None,
            primary_ok: 0,
            primary_deaths: 0,
            pending: None,
            stranded_at: None,
        }
    }

    /// Перенять память предшественника: ядро перезапустили или сменили
    /// стратегию, а что известно об узлах — по-прежнему верно. Незавершённые
    /// решения не наследуются: они принимались другой стратегией.
    pub fn inherit(mut self, old: &Brain) -> Self {
        for (tag, health) in &old.health {
            if self.knows(tag) {
                self.health.insert(tag.clone(), health.clone());
            }
        }
        self.sweeps = old.sweeps;
        self.judged = old.sweeps;
        self.last_sweep = old.last_sweep;
        if old.primary == self.primary {
            self.primary_deaths = old.primary_deaths;
            if self.knows(&old.routed) {
                self.routed = old.routed.clone();
            }
        }
        self
    }

    fn knows(&self, tag: &str) -> bool {
        tag == self.primary || self.is_safe(tag)
    }

    /// Можно ли мерить узел через ядро, не рискуя уронить его.
    pub fn is_safe(&self, tag: &str) -> bool {
        self.candidates.iter().any(|c| c == tag)
    }

    pub fn routed(&self) -> &str {
        &self.routed
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn primary(&self) -> &str {
        &self.primary
    }

    /// Пользователь выбрал сервер сам: он теперь и основной, и текущий.
    pub fn set_primary(&mut self, tag: &str) {
        self.primary = tag.to_string();
        self.routed = tag.to_string();
        self.primary_ok = 0;
        self.primary_deaths = 0;
        self.ahead = None;
        self.pending = None;
        self.stranded_at = None;
        self.judged = self.sweeps;
    }

    /// Узел признан мёртвым без замера — ядро упало, пока трафик шёл через него.
    pub fn mark_dead(&mut self, tag: &str, now: Instant) {
        let health = self.health.entry(tag.to_string()).or_default();
        health.fails = health.fails.max(FAIL_LIMIT);
        health.probed_at = Some(now);
        if tag == self.primary {
            self.primary_ok = 0;
        }
    }

    /// Результат одного замера: `None` — узел не ответил.
    pub fn report(&mut self, tag: &str, result: Option<u32>, now: Instant) {
        let health = self.health.entry(tag.to_string()).or_default();
        health.probed_at = Some(now);
        match result {
            Some(ms) => {
                health.samples.push_back(ms);
                while health.samples.len() > SAMPLES {
                    health.samples.pop_front();
                }
                health.fails = 0;
                health.ok_at = Some(now);
            }
            None => health.fails += 1,
        }
        if tag == self.primary && self.routed != self.primary {
            self.primary_ok = if result.is_some() { self.primary_ok + 1 } else { 0 };
        }
    }

    /// Результаты шага `Probe` целиком. Кусок обхода, замкнувший его, засчитывает
    /// обход завершённым.
    pub fn report_batch(&mut self, results: &[(String, Option<u32>)], now: Instant) {
        for (tag, result) in results {
            self.report(tag, *result, now);
        }
        if self.sweeping {
            self.sweeping = false;
            if self.sweep.is_empty() {
                self.finish_sweep(now);
            }
        }
    }

    fn finish_sweep(&mut self, now: Instant) {
        self.sweeps += 1;
        self.last_sweep = Some(now);
    }

    /// Селектор переключён на `to`.
    pub fn commit(&mut self, to: &str) {
        let reason = self.pending.take().map(|p| p.reason);
        if matches!(reason, Some(Reason::Dead { .. })) && self.routed == self.primary {
            self.primary_deaths += 1;
        }
        self.routed = to.to_string();
        self.primary_ok = 0;
        self.ahead = None;
        self.stranded_at = None;
    }

    /// Ядро отклонило переключение — решение забыто, следующее примется по
    /// новым замерам.
    pub fn abort(&mut self) {
        self.pending = None;
    }

    /// Следующий шаг поводыря.
    pub fn next(&mut self, now: Instant) -> Step {
        if let Some(step) = self.pending_step(now) {
            return step;
        }
        if let Some(pending) = self.judge(now) {
            self.pending = Some(pending);
            if let Some(step) = self.pending_step(now) {
                return step;
            }
        }

        let watched = self.watched_due(now);
        if !watched.is_empty() {
            self.sweeping = false;
            return Step::Probe(watched);
        }

        if self.sweep.is_empty() && self.sweep_due(now) {
            // Текущий и основной меряются своим расписанием — в обходе они лишние.
            let skip = self.watched();
            self.sweep = self
                .candidates
                .iter()
                .filter(|tag| !skip.contains(tag))
                .cloned()
                .collect();
            if self.sweep.is_empty() {
                self.finish_sweep(now);
            }
        }
        if !self.sweep.is_empty() {
            let chunk: Vec<String> = (0..CHUNK).filter_map(|_| self.sweep.pop_front()).collect();
            self.sweeping = true;
            return Step::Probe(chunk);
        }

        Step::Idle(self.until_next(now))
    }

    /// Довести начатый переход: перепроверить голову очереди или переключить.
    fn pending_step(&mut self, now: Instant) -> Option<Step> {
        loop {
            let head = self.pending.as_ref().and_then(|p| p.queue.front().cloned());
            let Some(tag) = head else {
                let reason = self.pending.take().map(|p| p.reason)?;
                return match reason {
                    Reason::Dead { .. } => {
                        self.stranded_at = Some(self.sweeps);
                        Some(Step::Stranded)
                    }
                    Reason::Recovered => {
                        self.primary_ok = 0;
                        None
                    }
                    _ => None,
                };
            };
            let pending = self.pending.as_mut()?;
            let health = self.health.get(&tag).cloned().unwrap_or_default();
            let checked = health.probed_at.is_some_and(|t| t >= pending.since);
            if checked && health.fails > 0 {
                pending.queue.pop_front();
                continue;
            }
            let fresh = health.alive()
                && health.ok_at.is_some_and(|t| now.duration_since(t) <= FRESH);
            if checked || fresh {
                return Some(Step::Switch {
                    from: self.routed.clone(),
                    to: tag,
                    reason: pending.reason.clone(),
                });
            }
            self.sweeping = false;
            return Some(Step::Probe(vec![tag]));
        }
    }

    /// Решение по накопленным замерам.
    fn judge(&mut self, now: Instant) -> Option<Pending> {
        let routed = self.health.get(&self.routed).cloned().unwrap_or_default();

        // Мёртвый текущий — вне зависимости от стратегии.
        if routed.fails >= FAIL_LIMIT {
            if self.stranded_at == Some(self.sweeps) {
                return None;
            }
            return Some(Pending {
                reason: Reason::Dead { fails: routed.fails },
                queue: self.alternatives(),
                since: now,
            });
        }
        if !routed.alive() {
            return None;
        }

        match self.cfg.strategy {
            Balancer::Manual => None,
            Balancer::Failover => {
                if self.routed != self.primary && self.primary_ok >= self.recover_needed() {
                    Some(Pending {
                        reason: Reason::Recovered,
                        queue: VecDeque::from([self.primary.clone()]),
                        since: now,
                    })
                } else {
                    None
                }
            }
            Balancer::Fastest => {
                if !self.take_round() {
                    return None;
                }
                // Текущий узел меряется каждые 20 секунд — его медиана свежая
                // и сглаживает случайный всплеск. Кандидат меряется раз в
                // обход, и медиана по трём обходам тянулась бы десять минут;
                // его берём по последнему замеру, а от шума бережёт серия.
                let Some(mine) = routed.delay() else {
                    return None;
                };
                let Some((best, theirs)) = self.fastest_alternative() else {
                    self.ahead = None;
                    return None;
                };
                if theirs + self.cfg.tolerance >= mine {
                    self.ahead = None;
                    return None;
                }
                let gain = mine - theirs;
                let streak = match &self.ahead {
                    Some((tag, n)) if *tag == best => n + 1,
                    _ => 1,
                };
                let first = self.rounds == 1;
                if first || streak >= STREAK {
                    self.ahead = None;
                    Some(Pending {
                        reason: if first {
                            Reason::Initial { gain }
                        } else {
                            Reason::Faster { gain }
                        },
                        queue: VecDeque::from([best]),
                        since: now,
                    })
                } else {
                    self.ahead = Some((best, streak));
                    None
                }
            }
            Balancer::Rotate => {
                // Первый обход — расстановка, ротация начинается со второго.
                if !self.take_round() || self.rounds < 2 {
                    return None;
                }
                let queue = self.rotation_queue();
                if queue.is_empty() {
                    return None;
                }
                Some(Pending {
                    reason: Reason::Rotation,
                    queue,
                    since: now,
                })
            }
        }
    }

    /// Одно решение на завершённый обход.
    fn take_round(&mut self) -> bool {
        if self.judged == self.sweeps {
            return false;
        }
        self.judged = self.sweeps;
        self.rounds += 1;
        true
    }

    /// Куда уходить с мёртвого узла: живые по задержке, затем ещё не
    /// мерянные — их проверит переход; известные мёртвые не предлагаются.
    fn alternatives(&self) -> VecDeque<String> {
        let mut alive: Vec<(&String, u32)> = Vec::new();
        let mut unknown: Vec<&String> = Vec::new();
        for tag in &self.candidates {
            if *tag == self.routed {
                continue;
            }
            match self.health.get(tag) {
                Some(h) if h.alive() => alive.push((tag, h.delay().unwrap_or(u32::MAX))),
                Some(h) if h.fails > 0 => {}
                _ => unknown.push(tag),
            }
        }
        alive.sort_by_key(|(_, delay)| *delay);
        let mut queue: VecDeque<String> = alive
            .into_iter()
            .map(|(tag, _)| tag.clone())
            .chain(unknown.into_iter().cloned())
            .collect();

        // «С резервом»: основной, если не мёртв, впереди всех.
        if self.cfg.strategy == Balancer::Failover
            && self.routed != self.primary
            && self.is_safe(&self.primary)
            && self.health.get(&self.primary).is_none_or(|h| h.fails == 0)
        {
            queue.retain(|tag| *tag != self.primary);
            queue.push_front(self.primary.clone());
        }
        queue
    }

    /// Самый быстрый из живых кандидатов по последнему замеру.
    fn fastest_alternative(&self) -> Option<(String, u32)> {
        self.candidates
            .iter()
            .filter(|tag| **tag != self.routed)
            .filter_map(|tag| {
                let h = self.health.get(tag)?;
                if !h.alive() {
                    return None;
                }
                Some((tag.clone(), h.latest()?))
            })
            .min_by_key(|(_, delay)| *delay)
    }

    /// Живые кандидаты, начиная со следующего за текущим по списку.
    fn rotation_queue(&self) -> VecDeque<String> {
        let n = self.candidates.len();
        let start = self
            .candidates
            .iter()
            .position(|tag| *tag == self.routed)
            .map_or(0, |i| i + 1);
        (0..n)
            .map(|k| &self.candidates[(start + k) % n])
            .filter(|tag| **tag != self.routed)
            .filter(|tag| self.health.get(*tag).is_some_and(Health::alive))
            .cloned()
            .collect()
    }

    fn recover_needed(&self) -> u32 {
        RECOVER_BASE << self.primary_deaths.saturating_sub(1).min(5)
    }

    /// Узлы со своим расписанием проверок: текущий и, на резерве, основной —
    /// если его можно мерить.
    fn watched(&self) -> Vec<String> {
        let mut tags = vec![self.routed.clone()];
        if self.cfg.strategy == Balancer::Failover
            && self.routed != self.primary
            && self.is_safe(&self.primary)
        {
            tags.push(self.primary.clone());
        }
        tags
    }

    fn watched_due(&self, now: Instant) -> Vec<String> {
        self.watched()
            .into_iter()
            .filter(|tag| self.probe_wait(tag, now).is_zero())
            .collect()
    }

    /// Сколько ждать до следующей проверки узла.
    fn probe_wait(&self, tag: &str, now: Instant) -> Duration {
        let Some(health) = self.health.get(tag) else {
            return Duration::ZERO;
        };
        let Some(probed_at) = health.probed_at else {
            return Duration::ZERO;
        };
        let every = if health.fails > 0 { RETRY_AFTER } else { PROBE_EVERY };
        every.saturating_sub(now.duration_since(probed_at))
    }

    fn sweep_wait(&self, now: Instant) -> Duration {
        match self.last_sweep {
            None => Duration::ZERO,
            Some(at) => self.cfg.interval.saturating_sub(now.duration_since(at)),
        }
    }

    fn sweep_due(&self, now: Instant) -> bool {
        self.sweep_wait(now).is_zero()
    }

    fn until_next(&self, now: Instant) -> Duration {
        let mut wait = self.sweep_wait(now);
        for tag in self.watched() {
            wait = wait.min(self.probe_wait(&tag, now));
        }
        wait.clamp(Duration::from_secs(1), IDLE_CAP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(180);

    fn brain(strategy: Balancer, primary: &str, candidates: &[&str]) -> Brain {
        Brain::new(
            Config {
                strategy,
                tolerance: 100,
                interval: INTERVAL,
            },
            primary,
            candidates.iter().map(|s| s.to_string()).collect(),
        )
    }

    fn probe(tags: &[&str]) -> Step {
        Step::Probe(tags.iter().map(|s| s.to_string()).collect())
    }

    fn ok(tag: &str, ms: u32) -> (String, Option<u32>) {
        (tag.into(), Some(ms))
    }

    fn miss(tag: &str) -> (String, Option<u32>) {
        (tag.into(), None)
    }

    fn switch(from: &str, to: &str, reason: Reason) -> Step {
        Step::Switch {
            from: from.into(),
            to: to.into(),
            reason,
        }
    }

    /// Модельное время: секунды от начала.
    struct Clock(Instant);

    impl Clock {
        fn new() -> Self {
            Self(Instant::now())
        }

        fn at(&self, secs: u64) -> Instant {
            self.0 + Duration::from_secs(secs)
        }
    }

    /// Подключились: текущий проверен, остальные обойдены.
    fn warm_up(b: &mut Brain, clock: &Clock, routed_ms: u32, others: &[(&str, u32)]) {
        let routed = b.routed().to_string();
        assert_eq!(b.next(clock.at(0)), probe(&[&routed]));
        b.report_batch(&[ok(&routed, routed_ms)], clock.at(0));
        let tags: Vec<&str> = others.iter().map(|(t, _)| *t).collect();
        assert_eq!(b.next(clock.at(0)), probe(&tags));
        let results: Vec<_> = others.iter().map(|(t, ms)| ok(t, *ms)).collect();
        b.report_batch(&results, clock.at(1));
    }

    #[test]
    fn a_dead_server_is_left_after_two_misses_for_the_best_live_one() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Failover, "A", &["A", "B", "C"]);
        warm_up(&mut b, &clock, 60, &[("B", 90), ("C", 40)]);
        assert!(matches!(b.next(clock.at(1)), Step::Idle(_)));

        // Плановая проверка текущего — раз в 20 секунд.
        assert_eq!(b.next(clock.at(20)), probe(&["A"]));
        b.report_batch(&[miss("A")], clock.at(20));
        // Одна осечка — ещё не приговор: перепроверка через пять секунд.
        assert!(matches!(b.next(clock.at(21)), Step::Idle(_)));
        assert_eq!(b.next(clock.at(25)), probe(&["A"]));
        b.report_batch(&[miss("A")], clock.at(25));

        // Две подряд — уходим на лучший из живых; его замер свежий, без
        // перепроверки.
        assert_eq!(
            b.next(clock.at(25)),
            switch("A", "C", Reason::Dead { fails: 2 })
        );
        b.commit("C");
        assert_eq!(b.routed(), "C");
        assert_eq!(b.primary(), "A");
    }

    #[test]
    fn failover_returns_to_the_primary_once_it_stays_up_and_backs_off() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Failover, "A", &["A", "B"]);
        warm_up(&mut b, &clock, 60, &[("B", 90)]);
        for t in [20, 25] {
            assert_eq!(b.next(clock.at(t)), probe(&["A"]));
            b.report_batch(&[miss("A")], clock.at(t));
        }
        assert_eq!(b.next(clock.at(25)), switch("A", "B", Reason::Dead { fails: 2 }));
        b.commit("B");

        // На резерве меряются оба: текущий и основной.
        assert_eq!(b.next(clock.at(25)), probe(&["B"]));
        b.report_batch(&[ok("B", 90)], clock.at(25));
        assert_eq!(b.next(clock.at(30)), probe(&["A"]));
        b.report_batch(&[ok("A", 60)], clock.at(30));
        assert!(matches!(b.next(clock.at(31)), Step::Idle(_)));
        assert_eq!(b.next(clock.at(50)), probe(&["B", "A"]));
        b.report_batch(&[ok("B", 90), ok("A", 60)], clock.at(50));
        assert!(matches!(b.next(clock.at(51)), Step::Idle(_)));
        assert_eq!(b.next(clock.at(70)), probe(&["B", "A"]));
        b.report_batch(&[ok("B", 90), ok("A", 60)], clock.at(70));
        // Три удачные проверки подряд — основной вернул себе трафик.
        assert_eq!(b.next(clock.at(70)), switch("B", "A", Reason::Recovered));
        b.commit("A");

        // Вторая смерть основного: возвращение уже требует шесть проверок.
        for t in [90, 95] {
            assert_eq!(b.next(clock.at(t)), probe(&["A"]));
            b.report_batch(&[miss("A")], clock.at(t));
        }
        assert_eq!(b.next(clock.at(95)), switch("A", "B", Reason::Dead { fails: 2 }));
        b.commit("B");
        let mut t = 95;
        for _ in 0..5 {
            t += 20;
            b.report_batch(&[ok("B", 90), ok("A", 60)], clock.at(t));
            assert!(matches!(b.next(clock.at(t)), Step::Idle(_) | Step::Probe(_)), "{t}");
        }
        b.report_batch(&[ok("B", 90), ok("A", 60)], clock.at(t + 20));
        assert_eq!(b.next(clock.at(t + 20)), switch("B", "A", Reason::Recovered));
    }

    #[test]
    fn fastest_switches_only_when_ahead_by_the_tolerance_twice_in_a_row() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Fastest, "A", &["A", "B"]);
        // Первый обход: B быстрее, но в пределах допуска — расстановка
        // оставляет всё как есть.
        warm_up(&mut b, &clock, 200, &[("B", 150)]);
        assert!(matches!(b.next(clock.at(1)), Step::Idle(_)));

        // Второй обход: B впереди на допуск — одного раза мало.
        assert_eq!(b.next(clock.at(181)), probe(&["A"]));
        b.report_batch(&[ok("A", 200)], clock.at(181));
        assert_eq!(b.next(clock.at(181)), probe(&["B"]));
        b.report_batch(&[ok("B", 90)], clock.at(182));
        assert!(matches!(b.next(clock.at(182)), Step::Idle(_)));

        // Третий: снова впереди — переходим.
        assert_eq!(b.next(clock.at(362)), probe(&["A"]));
        b.report_batch(&[ok("A", 200)], clock.at(362));
        assert_eq!(b.next(clock.at(362)), probe(&["B"]));
        b.report_batch(&[ok("B", 95)], clock.at(363));
        assert_eq!(
            b.next(clock.at(363)),
            switch("A", "B", Reason::Faster { gain: 105 })
        );
    }

    #[test]
    fn fastest_places_itself_right_after_the_first_round() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Fastest, "A", &["A", "B"]);
        warm_up(&mut b, &clock, 300, &[("B", 50)]);
        assert_eq!(
            b.next(clock.at(1)),
            switch("A", "B", Reason::Initial { gain: 250 })
        );
    }

    #[test]
    fn fastest_ignores_servers_within_the_tolerance() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Fastest, "A", &["A", "B"]);
        warm_up(&mut b, &clock, 100, &[("B", 40)]);
        // 60 мс выигрыша при допуске 100 — шум, а не повод.
        let mut t = 1;
        for _ in 0..4 {
            assert!(matches!(b.next(clock.at(t)), Step::Idle(_)));
            t += 180;
            assert_eq!(b.next(clock.at(t)), probe(&["A"]));
            b.report_batch(&[ok("A", 100)], clock.at(t));
            assert_eq!(b.next(clock.at(t)), probe(&["B"]));
            b.report_batch(&[ok("B", 40)], clock.at(t));
        }
        assert!(matches!(b.next(clock.at(t)), Step::Idle(_)));
    }

    #[test]
    fn rotation_walks_the_list_from_the_second_round_skipping_the_dead() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Rotate, "A", &["A", "B", "C"]);
        warm_up(&mut b, &clock, 60, &[("B", 70), ("C", 80)]);
        assert!(matches!(b.next(clock.at(1)), Step::Idle(_)));

        assert_eq!(b.next(clock.at(181)), probe(&["A"]));
        b.report_batch(&[ok("A", 60)], clock.at(181));
        assert_eq!(b.next(clock.at(181)), probe(&["B", "C"]));
        b.report_batch(&[miss("B"), ok("C", 80)], clock.at(182));
        // B упал — следующий живой по кругу за A это C.
        assert_eq!(b.next(clock.at(182)), switch("A", "C", Reason::Rotation));
        b.commit("C");

        assert_eq!(b.next(clock.at(362)), probe(&["C"]));
        b.report_batch(&[ok("C", 80)], clock.at(362));
        assert_eq!(b.next(clock.at(362)), probe(&["A", "B"]));
        b.report_batch(&[ok("A", 60), ok("B", 70)], clock.at(363));
        // За C по кругу идёт A.
        assert_eq!(b.next(clock.at(363)), switch("C", "A", Reason::Rotation));
    }

    #[test]
    fn stranded_when_nothing_is_alive_and_recovers_on_the_next_round() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Failover, "A", &["A", "B"]);
        assert_eq!(b.next(clock.at(0)), probe(&["A"]));
        b.report_batch(&[ok("A", 60)], clock.at(0));
        assert_eq!(b.next(clock.at(0)), probe(&["B"]));
        b.report_batch(&[miss("B")], clock.at(1));
        for t in [20, 25] {
            assert_eq!(b.next(clock.at(t)), probe(&["A"]));
            b.report_batch(&[miss("A")], clock.at(t));
        }
        // Уходить некуда: сообщить и не долбить решением каждую секунду.
        assert_eq!(b.next(clock.at(25)), Step::Stranded);
        assert_eq!(b.next(clock.at(26)), Step::Idle(Duration::from_secs(4)));

        // Следующий обход застал B живым — теперь есть куда.
        assert_eq!(b.next(clock.at(181)), probe(&["A"]));
        b.report_batch(&[miss("A")], clock.at(181));
        assert_eq!(b.next(clock.at(181)), probe(&["B"]));
        b.report_batch(&[ok("B", 70)], clock.at(182));
        assert_eq!(
            b.next(clock.at(182)),
            switch("A", "B", Reason::Dead { fails: 3 })
        );
    }

    #[test]
    fn a_stale_candidate_is_verified_before_the_switch() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Failover, "A", &["A", "B", "C"]);
        warm_up(&mut b, &clock, 60, &[("B", 90), ("C", 40)]);
        // Замеры B и C — двухминутной давности: перед переходом перепроверка.
        for t in [120, 125] {
            assert_eq!(b.next(clock.at(t)), probe(&["A"]));
            b.report_batch(&[miss("A")], clock.at(t));
        }
        assert_eq!(b.next(clock.at(125)), probe(&["C"]));
        b.report_batch(&[miss("C")], clock.at(126));
        // C тем временем умер — очередь идёт дальше.
        assert_eq!(b.next(clock.at(126)), probe(&["B"]));
        b.report_batch(&[ok("B", 95)], clock.at(127));
        assert_eq!(
            b.next(clock.at(127)),
            switch("A", "B", Reason::Dead { fails: 2 })
        );
    }

    #[test]
    fn a_fragile_primary_is_never_probed_while_traffic_is_on_a_backup() {
        let clock = Clock::new();
        // Основной F в кандидаты не входит: дозвон до него роняет ядро.
        let mut b = brain(Balancer::Failover, "F", &["B", "C"]);
        assert_eq!(b.next(clock.at(0)), probe(&["F"]));
        b.report_batch(&[miss("F")], clock.at(0));
        assert_eq!(b.next(clock.at(0)), probe(&["B", "C"]));
        b.report_batch(&[ok("B", 50), ok("C", 70)], clock.at(1));
        assert_eq!(b.next(clock.at(5)), probe(&["F"]));
        b.report_batch(&[miss("F")], clock.at(5));
        assert_eq!(b.next(clock.at(5)), switch("F", "B", Reason::Dead { fails: 2 }));
        b.commit("B");

        // Дальше меряется только текущий: основной остаётся в покое, а значит,
        // и возврата на него не будет.
        let mut t = 5;
        for _ in 0..30 {
            t += 20;
            let step = b.next(clock.at(t));
            assert!(
                !matches!(&step, Step::Probe(tags) if tags.iter().any(|tag| tag == "F")),
                "{step:?}"
            );
            b.report_batch(&[ok("B", 50)], clock.at(t));
        }
        assert_eq!(b.routed(), "B");
    }

    #[test]
    fn a_core_crash_counts_as_a_death_of_the_node_it_was_routed_through() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Failover, "F", &["B"]);
        b.report("B", Some(50), clock.at(0));
        b.mark_dead("F", clock.at(0));
        assert_eq!(b.next(clock.at(1)), switch("F", "B", Reason::Dead { fails: 2 }));
    }

    #[test]
    fn a_manual_pick_makes_the_new_server_primary_and_forgets_old_deaths() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Failover, "A", &["A", "B"]);
        warm_up(&mut b, &clock, 60, &[("B", 90)]);
        for t in [20, 25] {
            b.next(clock.at(t));
            b.report_batch(&[miss("A")], clock.at(t));
        }
        assert!(matches!(b.next(clock.at(25)), Step::Switch { .. }));
        b.commit("B");
        assert_eq!(b.primary_deaths, 1);

        b.set_primary("B");
        assert_eq!(b.primary(), "B");
        assert_eq!(b.routed(), "B");
        assert_eq!(b.primary_deaths, 0);
        assert_eq!(b.next(clock.at(26)), probe(&["B"]));
    }

    #[test]
    fn a_successor_inherits_health_and_the_current_node() {
        let clock = Clock::new();
        let mut old = brain(Balancer::Failover, "A", &["A", "B"]);
        warm_up(&mut old, &clock, 60, &[("B", 90)]);
        for t in [20, 25] {
            old.next(clock.at(t));
            old.report_batch(&[miss("A")], clock.at(t));
        }
        assert!(matches!(old.next(clock.at(25)), Step::Switch { .. }));
        old.commit("B");

        let new = brain(Balancer::Fastest, "A", &["A", "B"]).inherit(&old);
        // Трафик так и идёт через B, а про A известно, что он мёртв.
        assert_eq!(new.routed(), "B");
        assert_eq!(new.health["A"].fails, 2);
        assert_eq!(new.health["B"].delay(), Some(90));

        // Другой основной — чужая память о нём не переносится.
        let other = brain(Balancer::Failover, "B", &["A", "B"]).inherit(&old);
        assert_eq!(other.routed(), "B");
        assert_eq!(other.primary_deaths, 0);
    }

    #[test]
    fn idle_waits_for_the_nearest_of_the_next_probe_and_the_next_round() {
        let clock = Clock::new();
        let mut b = brain(Balancer::Fastest, "A", &["A", "B"]);
        warm_up(&mut b, &clock, 60, &[("B", 90)]);
        assert_eq!(b.next(clock.at(5)), Step::Idle(Duration::from_secs(15)));
        assert_eq!(b.next(clock.at(19)), Step::Idle(Duration::from_secs(1)));
    }
}
