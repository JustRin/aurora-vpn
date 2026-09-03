package com.aurora.vpn

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Where the tunnel is in its life, as seen by the service itself. */
enum class Phase { IDLE, STARTING, RUNNING }

/**
 * Who brought the tunnel down. Reported to Rust through `status`, so it can
 * tell a click on «Отключить» from a crash — the difference between a clean
 * disconnect and an automatic restart.
 */
object StopReason {
    /** Stopped by Rust itself, or never stopped. */
    const val NONE = ""
    /** Notification action, widget, quick-settings tile. */
    const val USER = "user"
    /** The system revoked the VPN: another client took the interface. */
    const val REVOKED = "revoked"
    /** libbox asked to stop on its own. */
    const val CORE = "core"
    /** The start itself failed. */
    const val ERROR = "error"
}

/** Counters from libbox's status stream: bytes and bytes per second. */
data class Traffic(
    val upSpeed: Long = 0,
    val downSpeed: Long = 0,
    val upTotal: Long = 0,
    val downTotal: Long = 0,
    val connections: Int = 0,
)

/**
 * The connection as Rust sees it — richer than the service's own view: Rust
 * knows the server's name and whether it actually answers. Empty until the
 * Rust runtime has come up in this process.
 */
data class RustStatus(
    val seq: Long = 0,
    /** `disconnected` · `connecting` · `connected` · `error`. */
    val state: String = "",
    /** `connecting` · `switching` · `up` · `down`. */
    val link: String = "",
    val serverName: String = "",
    val sinceMs: Long = 0,
)

/**
 * Shared state between the Tauri plugin (driven by Rust), the VpnService and
 * the surfaces that live outside the app — home-screen widgets and the
 * quick-settings tile. Everything runs in one process; this object is the only
 * channel they need.
 */
object VpnState {
    /** libbox `Setup` must run exactly once per process. */
    val libboxReady = AtomicBoolean(false)

    @Volatile var phase = Phase.IDLE

    /** What Rust polls through `status`. */
    val running: Boolean get() = phase == Phase.RUNNING

    @Volatile var lastError = ""

    /**
     * A localized hint for [lastError] when the service refused to start on
     * its own (no consent, no config) — what a widget shows instead of the
     * raw message. Zero when there is none.
     */
    @Volatile var lastErrorHint = 0

    @Volatile var stopReason = StopReason.NONE

    /** Wall clock of the moment the box came up — Rust's `since_ms` when it adopts the tunnel. */
    @Volatile var startedAtMs = 0L

    /** Same moment on the `elapsedRealtime` clock, which is what a widget Chronometer counts from. */
    @Volatile var startedAtElapsed = 0L

    @Volatile var traffic = Traffic()

    /** Outbound the selector currently routes through, straight from libbox. */
    @Volatile var selectedTag = ""

    @Volatile var rust = RustStatus()

    /** The live service instance, when the tunnel is up or coming up. */
    @Volatile var service: AuroraVpnService? = null

    /**
     * One-shot completion for a pending `start` command: called with `null`
     * once libbox is up, or with an error message when it refused the config.
     */
    @Volatile var startCallback: ((String?) -> Unit)? = null

    fun finishStart(error: String?) {
        val callback = startCallback
        startCallback = null
        callback?.invoke(error)
    }

    // ------------------------------------------------------- events to Rust

    /**
     * Events the Rust side subscribed to (`VpnPlugin.watch`): a tunnel started
     * or stopped by something other than Rust, and a request to connect that
     * came in through the launcher. Absent until the Rust runtime is up.
     */
    @Volatile var sink: ((kind: String, extras: Map<String, String>) -> Unit)? = null

    /**
     * A widget or tile asked to connect but the service could not do it alone
     * (no VPN consent yet, or no saved config), so the app was opened instead.
     * Held here until Rust is listening, then handed over.
     */
    @Volatile var pendingConnect = false

    fun emit(kind: String, extras: Map<String, String> = emptyMap()) {
        try {
            sink?.invoke(kind, extras)
        } catch (_: Exception) {
            // The channel is gone with the runtime that owned it.
        }
    }

    fun requestConnect() {
        pendingConnect = true
        flushPending()
    }

    fun flushPending() {
        if (sink == null || !pendingConnect) return
        pendingConnect = false
        emit("connectRequested")
    }

    // ------------------------------------------------------------- activity

    @Volatile private var current: MainActivity? = null

    /**
     * The activity that can host a system dialog right now, or null while none
     * exists. Tauri hands every plugin the first activity and never swaps it
     * (`PluginManager.onActivityCreate` returns early on the second one), so
     * after Android recreated the UI the plugin's own `activity` is a dead one:
     * still fine as a Context, useless for anything the user has to answer.
     * This is the way to the live one.
     */
    val activity: MainActivity?
        get() = current?.takeUnless { it.isDestroyed || it.isFinishing }

    fun bindActivity(activity: MainActivity) {
        current = activity
    }

    fun unbindActivity(activity: MainActivity) {
        // Only the incumbent may retract itself: a destroy that lands after its
        // replacement has bound must not unbind the live activity. Dropping the
        // reference is what keeps a destroyed activity from outliving itself
        // here — the getter above already refuses to hand one out.
        if (current === activity) {
            current = null
        }
    }

    // -------------------------------------------------------------- consent

    /**
     * One-shot completion for a pending VPN-consent request. Two things can
     * answer it — the result of the system dialog, and the re-check
     * `MainActivity.onResume` runs when that result died with the activity that
     * launched it — so the hand-off has to be atomic: the loser must not
     * resolve the same invoke a second time.
     */
    private val consent = AtomicReference<((Boolean) -> Unit)?>()

    val consentPending: Boolean
        get() = consent.get() != null

    fun awaitConsent(callback: (Boolean) -> Unit) {
        // Nothing would ever answer a displaced request, and its caller is a
        // blocked Rust thread; deny it now rather than leak it.
        consent.getAndSet(callback)?.invoke(false)
    }

    fun finishConsent(granted: Boolean) {
        consent.getAndSet(null)?.invoke(granted)
    }
}
