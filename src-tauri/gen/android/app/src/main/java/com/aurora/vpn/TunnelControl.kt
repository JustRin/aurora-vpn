package com.aurora.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import java.io.File
import java.util.Locale

private const val TAG = "AuroraTunnel"

/**
 * What the service needs to bring the tunnel up without the Rust runtime: the
 * path of the last config Rust generated, plus the name of the server for the
 * widgets to show before Rust is around to tell them.
 */
object TunnelPrefs {
    private const val FILE = "tunnel"
    private const val KEY_CONFIG = "configPath"
    private const val KEY_SERVER = "serverName"

    private fun prefs(context: Context) =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun saveConfigPath(context: Context, path: String) {
        prefs(context).edit().putString(KEY_CONFIG, path).apply()
    }

    fun configPath(context: Context): String? = prefs(context).getString(KEY_CONFIG, null)

    fun saveServerName(context: Context, name: String) {
        prefs(context).edit().putString(KEY_SERVER, name).apply()
    }

    fun serverName(context: Context): String = prefs(context).getString(KEY_SERVER, "") ?: ""
}

/** Starting and stopping the tunnel from outside the app: widgets and the tile. */
object TunnelControl {
    fun hasConsent(context: Context): Boolean = VpnService.prepare(context) == null

    fun hasConfig(context: Context): Boolean =
        TunnelPrefs.configPath(context)?.let { File(it).isFile } == true

    /** Whether the service can come up without an activity: consent granted, config on disk. */
    fun canStartSilently(context: Context): Boolean = hasConsent(context) && hasConfig(context)

    fun serviceIntent(context: Context, action: String): Intent =
        Intent(context, AuroraVpnService::class.java).setAction(action)

    /**
     * The app itself. With `connect`, the activity asks Rust to connect as
     * soon as it is up — the path for everything the service cannot do
     * alone: the VPN consent dialog, or a first connection with no config yet.
     */
    fun openAppIntent(context: Context, connect: Boolean): Intent =
        Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(MainActivity.EXTRA_CONNECT, connect)

    /**
     * Connect from a context the system treats as user-driven (the tile).
     * Returns false when the service cannot do it alone and the app has to
     * be opened instead.
     */
    fun start(context: Context): Boolean {
        if (!canStartSilently(context)) return false
        return try {
            ContextCompat.startForegroundService(
                context,
                serviceIntent(context, AuroraVpnService.ACTION_CONNECT),
            )
            true
        } catch (e: Exception) {
            // Android 12+ refuses a foreground start it does not consider
            // user-driven; the app can always be opened instead.
            Log.w(TAG, "foreground start refused: ${e.message}")
            false
        }
    }

    /** Same process as the service, so a stop is a plain call. */
    fun stop() {
        VpnState.service?.stopTunnel(StopReason.USER)
    }

    /** Outbound tags are «index-name» (config.rs, sanitize_tag); nameless nodes get «node-index». */
    private val TAG_INDEX = Regex("^\\d+-")
    private val TAG_NAMELESS = Regex("^node-\\d+$")

    /**
     * What to call the server, best source first: the exact name Rust
     * reported for this connection; the selector's live tag from libbox with
     * its index prefix stripped (names only lose punctuation on the way in),
     * which is all a tunnel started without Rust knows; and the last name Rust
     * ever reported, for the moment before the box has said anything. Empty
     * when none of them knows.
     */
    fun serverLabel(context: Context): String {
        val rust = VpnState.rust
        if (rust.state.isNotEmpty() && rust.serverName.isNotEmpty()) return rust.serverName
        val tag = VpnState.selectedTag
        if (tag.isNotEmpty() && !TAG_NAMELESS.matches(tag)) {
            val bare = tag.replaceFirst(TAG_INDEX, "")
            if (bare.isNotEmpty()) return bare
        }
        return TunnelPrefs.serverName(context)
    }
}

/**
 * Fan-out for state changes to every surface that lives outside the app:
 * widgets, the quick-settings tile, and the status stream that feeds them.
 */
object TunnelBus {
    /** The tunnel changed state — everything redraws. */
    fun changed(context: Context) {
        val app = context.applicationContext
        WidgetUpdater.updateAll(app)
        AuroraTileService.refresh(app)
        VpnState.service?.syncStats()
    }

    /** A fresh traffic sample: only the widgets that show numbers care. */
    fun trafficTick(context: Context) {
        WidgetUpdater.updateTraffic(context.applicationContext)
    }

    /** A widget was added or removed: the status stream may have become (un)necessary. */
    fun widgetsChanged(@Suppress("UNUSED_PARAMETER") context: Context) {
        VpnState.service?.syncStats()
    }
}

/** Byte formatting that matches the app's own (`format.ts`), units included. */
object Fmt {
    fun bytes(context: Context, value: Long): String {
        val names = context.getString(R.string.widget_byte_units).split('|')
        if (value <= 0) return "0 ${names[0]}"
        var scaled = value.toDouble()
        var unit = 0
        while (scaled >= 1024 && unit < names.size - 1) {
            scaled /= 1024
            unit++
        }
        // A widget line is short: one decimal only where it carries information.
        val digits = when {
            unit == 0 -> 0
            scaled < 10 -> 1
            else -> 0
        }
        return String.format(Locale.getDefault(), "%.${digits}f %s", scaled, names[unit])
    }

    fun speed(context: Context, bytesPerSecond: Long): String =
        bytes(context, bytesPerSecond) + context.getString(R.string.widget_per_second)
}
