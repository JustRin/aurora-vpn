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
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import io.nekohasekai.libbox.Libbox

@InvokeArg
class StartArgs {
    var configPath: String = ""
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
        VpnState.service?.stopTunnel()
        invoke.resolve(JSObject().put("ok", true))
    }

    @Command
    fun status(invoke: Invoke) {
        invoke.resolve(
            JSObject()
                .put("running", VpnState.running)
                .put("lastError", VpnState.lastError),
        )
    }

    @Command
    fun version(invoke: Invoke) {
        invoke.resolve(JSObject().put("version", Libbox.version()))
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
