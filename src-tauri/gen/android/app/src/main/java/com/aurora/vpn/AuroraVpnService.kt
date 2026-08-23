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
 * The service is intentionally dumb: all decisions (config generation, when to
 * start or stop) are made on the Rust side and arrive via [VpnPlugin].
 */
class AuroraVpnService : VpnService(), CommandServerHandler {

    // Both are written on the `libbox-start` thread and read by `closeBox` on
    // the main one. Today a happens-before edge exists by accident — the start
    // thread writes the volatile `VpnState.running` afterwards — but teardown is
    // the last place to lean on an accident: a stale `null` here is a tunnel
    // left up with every route still pointing into it.
    @Volatile
    private var server: CommandServer? = null

    /** Kept because it owns the TUN descriptor that [closeBox] has to release. */
    @Volatile
    private var platform: BoxPlatform? = null

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
                stopTunnel()
                return START_NOT_STICKY
            }
        }

        startAsForeground()

        val configPath = intent?.getStringExtra(EXTRA_CONFIG_PATH)
        if (configPath.isNullOrEmpty()) {
            VpnState.finishStart("сервису не передан путь к конфигурации")
            stopSelf()
            return START_NOT_STICKY
        }

        // StartOrReloadService blocks while the box comes up — never on main.
        thread(name = "libbox-start") {
            try {
                val content = File(configPath).readText()
                val server = this.server ?: run {
                    val platform = BoxPlatform(this)
                    this.platform = platform
                    Libbox.newCommandServer(this, platform).also { this.server = it }
                }
                server.startOrReloadService(content, OverrideOptions())
                VpnState.running = true
                VpnState.lastError = ""
                VpnState.finishStart(null)
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                Log.e(TAG, "libbox start failed: $message")
                VpnState.running = false
                VpnState.lastError = message
                // The Rust side also tails the log file; make sure the reason
                // lands there even when libbox died before opening it.
                appendFatalToLog(configPath, message)
                VpnState.finishStart(message)
                stopTunnel()
            }
        }
        return START_STICKY
    }

    /** The system revoked the VPN (another app took it, or the user killed it). */
    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by the system")
        stopTunnel()
    }

    override fun onDestroy() {
        closeBox()
        VpnState.service = null
        super.onDestroy()
    }

    fun stopTunnel() {
        closeBox()
        VpnState.running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeBox() {
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
        VpnState.running = false
    }

    // ------------------------------------------------- CommandServerHandler

    override fun serviceStop() {
        stopTunnel()
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
        const val EXTRA_CONFIG_PATH = "configPath"
    }
}
