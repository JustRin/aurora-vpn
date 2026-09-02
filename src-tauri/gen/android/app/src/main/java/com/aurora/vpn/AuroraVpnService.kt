package com.aurora.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import android.util.Log
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import java.io.File
import kotlin.concurrent.thread

private const val TAG = "AuroraVpnService"
private const val CHANNEL_TUNNEL = "vpn"
private const val CHANNEL_ALERTS = "vpn-alerts"
private const val NOTIFICATION_ID = 1

/**
 * Foreground service that owns the tunnel: it hosts libbox (sing-box compiled
 * as a library), hands it the TUN descriptor through [BoxPlatform.openTun] and
 * keeps a status-bar notification alive for as long as the VPN runs.
 *
 * The service is deliberately dumb: config generation and the decision to
 * connect are made on the Rust side and arrive via [VpnPlugin]. The one thing
 * it can do alone is bring the *last* config back up — that is what a
 * home-screen widget, the quick-settings tile and a sticky restart after the
 * system killed the process all ask for, and none of them has a Rust runtime
 * to ask. Rust learns about such a tunnel through [VpnState.emit] and adopts
 * it when it comes up.
 */
class AuroraVpnService : VpnService(), CommandServerHandler {

    // Both are written on the `libbox-start` thread and read by `closeBox` on
    // the main one. Today a happens-before edge exists by accident — the start
    // thread writes the volatile `VpnState.phase` afterwards — but teardown is
    // the last place to lean on an accident: a stale `null` here is a tunnel
    // left up with every route still pointing into it.
    @Volatile
    private var server: CommandServer? = null

    /** Kept because it owns the TUN descriptor that [closeBox] has to release. */
    @Volatile
    private var platform: BoxPlatform? = null

    /** Status stream feeding the widgets; alive only while the box runs and a widget shows numbers. */
    private var stats: StatsClient? = null

    override fun onCreate() {
        super.onCreate()
        VpnState.service = this

        if (VpnState.libboxReady.compareAndSet(false, true)) {
            val options = SetupOptions()
            options.basePath = filesDir.absolutePath
            options.workingPath = File(filesDir, "libbox").absolutePath
            options.tempPath = cacheDir.absolutePath
            // Workaround for golang/go#68760 crashes on Android.
            options.fixAndroidStack = true
            options.logMaxLines = 3000L
            Libbox.setup(options)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // The notification action: sent with getService, no foreground
                // promise attached.
                stopTunnel(StopReason.USER)
                return START_NOT_STICKY
            }
            ACTION_TOGGLE -> {
                // Widgets send this through getForegroundService whether the
                // tunnel is up or not, and every such start has to be answered
                // with startForeground — a stop included — or the system kills
                // the app for a promise not kept.
                startAsForeground()
                if (VpnState.phase != Phase.IDLE) {
                    stopTunnel(StopReason.USER)
                    return START_NOT_STICKY
                }
                return startFromSaved()
            }
            ACTION_CONNECT -> {
                startAsForeground()
                return startFromSaved()
            }
        }

        startAsForeground()

        if (intent == null) {
            // START_STICKY restart after the system killed the process: the
            // user never asked for the tunnel to go away, so bring it back
            // with the config it had.
            return startFromSaved()
        }

        val configPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
        if (configPath.isNullOrEmpty()) {
            VpnState.finishStart("сервису не передан путь к конфигурации")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        // Remembered for the surfaces that start the tunnel without Rust.
        TunnelPrefs.saveConfigPath(this, configPath)
        launch(configPath, external = false)
        return START_STICKY
    }

    /**
     * Bring the tunnel up on the service's own: the last config Rust handed
     * over, no runtime required. Consent and config are checked here again
     * even though the widget checks them before choosing its intent — the
     * state can change between a widget redraw and a tap.
     */
    private fun startFromSaved(): Int {
        if (VpnState.phase != Phase.IDLE) {
            // Already up or on its way.
            return START_STICKY
        }
        val path = TunnelPrefs.configPath(this)
        if (path == null || !File(path).isFile) {
            giveUp("нет сохранённой конфигурации — откройте приложение", R.string.widget_err_no_config)
            return START_NOT_STICKY
        }
        if (VpnService.prepare(this) != null) {
            // Consent needs an activity; the widget renders its button to open
            // the app once it sees this.
            giveUp("нет разрешения на VPN — откройте приложение", R.string.widget_err_no_consent)
            return START_NOT_STICKY
        }
        launch(path, external = true)
        return START_STICKY
    }

    private fun giveUp(message: String, hint: Int) {
        Log.w(TAG, message)
        VpnState.lastError = message
        VpnState.lastErrorHint = hint
        VpnState.stopReason = StopReason.ERROR
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        TunnelBus.changed(this)
    }

    private fun launch(configPath: String, external: Boolean) {
        VpnState.phase = Phase.STARTING
        VpnState.stopReason = StopReason.NONE
        VpnState.lastError = ""
        VpnState.lastErrorHint = 0
        TunnelBus.changed(this)

        // StartOrReloadService blocks while the box comes up — never on main.
        thread(name = "libbox-start") {
            try {
                val content = File(configPath).readText()
                val server = this.server ?: run {
                    val platform = BoxPlatform(this)
                    this.platform = platform
                    Libbox.newCommandServer(this, platform).also {
                        this.server = it
                        openCommandSocket(it)
                    }
                }
                server.startOrReloadService(content, OverrideOptions())
                VpnState.startedAtMs = System.currentTimeMillis()
                VpnState.startedAtElapsed = SystemClock.elapsedRealtime()
                VpnState.traffic = Traffic()
                VpnState.phase = Phase.RUNNING
                VpnState.lastError = ""
                VpnState.finishStart(null)
                TunnelBus.changed(this)
                if (external) {
                    VpnState.emit("started", mapOf("source" to "external"))
                }
                syncStats()
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                Log.e(TAG, "libbox start failed: $message")
                VpnState.lastError = message
                // The Rust side also tails the log file; make sure the reason
                // lands there even when libbox died before opening it.
                appendFatalToLog(configPath, message)
                VpnState.finishStart(message)
                stopTunnel(StopReason.ERROR)
            }
        }
    }

    /**
     * The command socket is how this process asks the running box for its
     * counters ([StatsClient]): a unix socket under basePath that libbox's own
     * client dials. Losing it costs the widgets their numbers, not the tunnel.
     */
    private fun openCommandSocket(server: CommandServer) {
        try {
            server.start()
        } catch (e: Exception) {
            Log.w(TAG, "command socket unavailable: ${e.message}")
        }
    }

    /**
     * Start or stop the status stream. It runs only while the box is up and
     * some widget shows traffic — a phone with the toggle alone on its home
     * screen should not pay for a stream nobody reads.
     */
    fun syncStats() {
        val wanted = VpnState.phase == Phase.RUNNING && WidgetUpdater.wantsTraffic(this)
        synchronized(this) {
            val current = stats
            if (wanted && current == null) {
                stats = StatsClient(this).also { it.start() }
            } else if (!wanted && current != null) {
                current.close()
                stats = null
            }
        }
    }

    /** The system revoked the VPN (another app took it, or the user killed it). */
    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by the system")
        stopTunnel(StopReason.REVOKED)
    }

    override fun onDestroy() {
        closeBox()
        VpnState.service = null
        super.onDestroy()
    }

    /**
     * Take the tunnel down. Safe to call when it is already down — then it
     * leaves [VpnState.stopReason] alone: the reason on record belongs to the
     * stop that actually happened, and Rust reads it to tell a click on
     * «Отключить» from a crash it should recover from.
     */
    fun stopTunnel(reason: String) {
        val wasUp = VpnState.phase != Phase.IDLE || server != null
        closeBox()
        if (wasUp) {
            VpnState.stopReason = reason
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        TunnelBus.changed(this)
        if (wasUp) {
            VpnState.emit("stopped", mapOf("reason" to reason))
        }
    }

    private fun closeBox() {
        synchronized(this) {
            stats?.close()
            stats = null
        }
        val server = this.server
        if (server != null) {
            this.server = null
            try {
                server.closeService()
            } catch (e: Exception) {
                Log.w(TAG, "closeService: ${e.message}")
            }
            try {
                server.close()
            } catch (e: Exception) {
                Log.w(TAG, "close: ${e.message}")
            }
        }
        // After the engine, never before: stopping the box is what releases
        // libbox's own copy of the descriptor, and the interface only goes down
        // once both are gone. Deliberately outside the `server != null` guard —
        // a start that failed partway can leave an interface with no engine
        // behind it, and that must still come down.
        platform?.closeTun()
        platform = null
        VpnState.phase = Phase.IDLE
        VpnState.traffic = Traffic()
        VpnState.selectedTag = ""
    }

    // ------------------------------------------------- CommandServerHandler

    override fun serviceStop() {
        stopTunnel(StopReason.CORE)
    }

    override fun serviceReload() {
        // Reload always arrives as a fresh `start` from the Rust side.
    }

    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus()

    override fun setSystemProxyEnabled(enabled: Boolean) {}

    override fun writeDebugMessage(message: String) {
        Log.d(TAG, message)
    }

    // ---------------------------------------------------------- notification

    private fun startAsForeground() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_TUNNEL,
                    getString(R.string.vpn_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, AuroraVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_TUNNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("Aurora VPN")
            .setContentText(getString(R.string.vpn_active))
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(
                Notification.Action.Builder(null, getString(R.string.vpn_disconnect), stop).build(),
            )
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /** Rule actions (`notify`) surfaced by libbox. */
    fun showRuleNotification(title: String, body: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ALERTS,
                    getString(R.string.vpn_alerts_channel_name),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
            )
        }
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ALERTS)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        try {
            manager.notify(
                (System.currentTimeMillis() % 10000).toInt() + 10,
                builder
                    .setContentTitle(title)
                    .setContentText(body)
                    .setSmallIcon(R.drawable.ic_notification)
                    .build(),
            )
        } catch (_: Exception) {
            // Notifications denied — the event still reaches the log page.
        }
    }

    /** Make a pre-log-file failure visible to the Rust log tail. */
    private fun appendFatalToLog(configPath: String, message: String) {
        try {
            val config = org.json.JSONObject(File(configPath).readText())
            val output = config.optJSONObject("log")?.optString("output")
            if (!output.isNullOrEmpty()) {
                File(output).appendText("FATAL start: $message\n")
            }
        } catch (_: Exception) {
        }
    }

    companion object {
        const val ACTION_STOP = "com.aurora.vpn.STOP"
        /** Widgets: up when down, down when up. */
        const val ACTION_TOGGLE = "com.aurora.vpn.TOGGLE"
        /** The tile: up with the last config, no-op when already up. */
        const val ACTION_CONNECT = "com.aurora.vpn.CONNECT"
        const val EXTRA_CONFIG_PATH = "configPath"
    }
}
