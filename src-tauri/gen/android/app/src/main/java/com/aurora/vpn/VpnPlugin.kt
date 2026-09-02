package com.aurora.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
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
        // Notifications are cosmetic (the FGS runs without them); ask once,
        // never block the tunnel on the answer.
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            try {
                ActivityCompat.requestPermissions(
                    activity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001,
                )
            } catch (e: Exception) {
                // Tauri hands every plugin the first activity and never swaps it
                // (PluginManager.onActivityCreate returns early on the second
                // one), so after Android recreated the activity this one is
                // dead and cannot host a dialog. Cosmetic means cosmetic: the
                // tunnel still starts.
                Log.w("VpnPlugin", "notification permission prompt skipped: ${e.message}")
            }
        }

        val intent = VpnService.prepare(activity)
        if (intent == null) {
            invoke.resolve(JSObject().put("granted", true))
        } else {
            startActivityForResult(invoke, intent, "onPrepareResult")
        }
    }

    @ActivityCallback
    fun onPrepareResult(invoke: Invoke, result: ActivityResult) {
        invoke.resolve(JSObject().put("granted", result.resultCode == Activity.RESULT_OK))
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
