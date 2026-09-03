package com.aurora.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import io.nekohasekai.libbox.Libbox

@InvokeArg
class StartArgs {
    var configPath: String = ""
}

@InvokeArg
class WatchArgs {
    lateinit var channel: Channel
}

@InvokeArg
class SyncArgs {
    /** Monotonic: a late delivery must not overwrite a newer status. */
    var seq: Long = 0
    var state: String = ""
    var link: String = ""
    var serverName: String = ""
    var sinceMs: Long = 0
}

/**
 * The Rust ⇄ Kotlin bridge (`core::android` on the other side). Commands are
 * invoked with `run_mobile_plugin`, so every `resolve` value must match the
 * serde struct the Rust caller deserializes.
 */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {

    // ------------------------------------------------------------- consent

    @Command
    fun prepare(invoke: Invoke) {
        // `activity` is the one Tauri handed the plugin at startup and never
        // swapped (PluginManager.onActivityCreate returns early on the second
        // one), so once Android has recreated the UI it is a dead activity:
        // still a working Context, but unable to host anything the user has to
        // answer. Those go to the live one.
        val live = VpnState.activity

        // Notifications are cosmetic (the FGS runs without them); ask once,
        // never block the tunnel on the answer — not even on there being a
        // window to ask in.
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            live?.requestNotificationPermission()
        }

        val intent = VpnService.prepare(activity)
        if (intent == null) {
            invoke.resolve(JSObject().put("granted", true))
            return
        }
        if (live == null) {
            invoke.reject("нет окна для системного запроса разрешения")
            return
        }
        // Armed before the launch, because the answer may outlive this activity
        // and come back through MainActivity.onResume instead of the launcher.
        VpnState.awaitConsent { granted ->
            invoke.resolve(JSObject().put("granted", granted))
        }
        live.requestVpnConsent(intent)
    }

    // ------------------------------------------------------------- tunnel

    @Command
    fun start(invoke: Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)
        if (args.configPath.isEmpty()) {
            invoke.reject("не указан путь к конфигурации")
            return
        }

        VpnState.startCallback = { error ->
            if (error == null) {
                invoke.resolve(JSObject().put("ok", true))
            } else {
                invoke.reject(error)
            }
        }

        val intent = Intent(activity, AuroraVpnService::class.java)
            .putExtra(AuroraVpnService.EXTRA_CONFIG_PATH, args.configPath)
        ContextCompat.startForegroundService(activity, intent)
    }

    @Command
    fun stop(invoke: Invoke) {
        // Rust's own decision: no reason to record, it already knows.
        VpnState.service?.stopTunnel(StopReason.NONE)
        invoke.resolve(JSObject().put("ok", true))
    }

    @Command
    fun status(invoke: Invoke) {
        invoke.resolve(
            JSObject()
                .put("running", VpnState.running)
                .put("phase", VpnState.phase.name.lowercase())
                .put("lastError", VpnState.lastError)
                .put("stopReason", VpnState.stopReason)
                .put("startedAtMs", VpnState.startedAtMs),
        )
    }

    @Command
    fun version(invoke: Invoke) {
        invoke.resolve(JSObject().put("version", Libbox.version()))
    }

    // ------------------------------------------------------------ outside

    /**
     * Subscribe Rust to what happens to the tunnel behind its back: a widget
     * or the tile starting it (`started`), anything stopping it (`stopped`,
     * with the reason), and the launcher asking for a connection the service
     * could not make alone (`connectRequested`).
     */
    @Command
    fun watch(invoke: Invoke) {
        val args = invoke.parseArgs(WatchArgs::class.java)
        val channel = args.channel
        VpnState.sink = { kind, extras ->
            val payload = JSObject().put("kind", kind)
            for ((key, value) in extras) payload.put(key, value)
            channel.send(payload)
        }
        // A request that arrived before Rust was listening.
        VpnState.flushPending()
        invoke.resolve(JSObject().put("ok", true))
    }

    /**
     * Rust's view of the connection, pushed on every status change: the
     * widgets and the tile show the server's name and whether it answers —
     * things only Rust knows.
     */
    @Command
    fun syncStatus(invoke: Invoke) {
        val args = invoke.parseArgs(SyncArgs::class.java)
        if (args.seq >= VpnState.rust.seq) {
            VpnState.rust = RustStatus(
                seq = args.seq,
                state = args.state,
                link = args.link,
                serverName = args.serverName,
                sinceMs = args.sinceMs,
            )
            if (args.serverName.isNotEmpty()) {
                TunnelPrefs.saveServerName(activity, args.serverName)
            }
            TunnelBus.changed(activity)
        }
        invoke.resolve(JSObject().put("ok", true))
    }

    // ------------------------------------------------------------ packages

    /** Installed apps for the split-tunnel picker. */
    @Command
    fun listPackages(invoke: Invoke) {
        val pm = activity.packageManager
        val installed = pm.getInstalledApplications(0)
        val packages = JSArray()
        for (app in installed) {
            if (app.packageName == activity.packageName) continue
            val entry = JSObject()
                .put("name", app.loadLabel(pm).toString())
                .put("package", app.packageName)
                .put("system", (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0)
            packages.put(entry)
        }
        invoke.resolve(JSObject().put("packages", packages))
    }
}
