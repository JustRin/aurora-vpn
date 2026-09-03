package com.aurora.vpn

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.ViewGroup
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebView
import androidx.annotation.RequiresApi
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner

private const val TAG = "WebViewRendererGuard"

/**
 * What happens when the WebView's renderer dies under us.
 *
 * From API 26 the renderer is a separate, low-priority process, so the system
 * kills it whenever memory gets tight — and a page can also crash it outright.
 * Either way the framework asks the [android.webkit.WebViewClient] what to do,
 * and the default answer, `false`, means «kill the app process». On a normal
 * app that is the right default: the process was only there to draw.
 *
 * Not here. [AuroraVpnService] holds the TUN descriptor and libbox in *this*
 * process — see `docs/architecture.md`, «Android»: on Android the engine has
 * to live where the file descriptor does. So the framework's default trades a
 * dead renderer for a dropped tunnel, and users see the VPN disconnect itself
 * for no reason they can name. Answering `true` keeps the process, and with it
 * the service, its routes and its notification.
 *
 * That leaves the UI to rebuild. The dead WebView is unusable and has to leave
 * the hierarchy before anything else touches it; after that there are two
 * honest outcomes, and which one is right depends on whether anyone is
 * looking:
 *
 *  - on screen, and not already rebuilt a moment ago → [Activity.recreate].
 *    `MainActivity.claimRecreation` is what makes this work: wry keeps the
 *    webview state across the destroy, and the next `onActivityCreate` builds
 *    a *new* `RustWebView` from it — not the corpse we just destroyed.
 *  - in the background, or a second death inside [REBUILD_COOLDOWN_MS] → just
 *    [Activity.finish]. Rebuilding a UI nobody is watching is what memory
 *    pressure was complaining about, and rebuilding into a page that keeps
 *    killing its renderer is a loop. Tapping the notification starts a fresh
 *    activity whenever the user actually wants one.
 *
 * Wired into `RustWebViewClient` at build time; `.cargo/config.toml`
 * explains why it cannot simply be written there by hand.
 */
object WebViewRendererGuard {

    /** Long enough that a page crashing on every load gives up after one try. */
    private const val REBUILD_COOLDOWN_MS = 30_000L

    /** Main thread only — every `WebViewClient` callback arrives on it. */
    private var lastRebuildAt: Long? = null

    @RequiresApi(Build.VERSION_CODES.O)
    fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
        Log.e(
            TAG,
            "renderer gone: didCrash=${detail.didCrash()}" +
                " priorityAtExit=${detail.rendererPriorityAtExit()}" +
                " tunnelRunning=${VpnState.running}",
        )

        // Required before anything else: nothing may be called on this WebView
        // again, and leaving it in the hierarchy is what turns a dead renderer
        // into a crash somewhere later.
        (view.parent as? ViewGroup)?.removeView(view)
        view.destroy()

        val activity = activityOf(view.context)
        if (activity == null || activity.isFinishing || activity.isDestroyed) {
            // No UI left to rebuild — which was the whole point: the tunnel is
            // not the activity's to lose.
            return true
        }

        val visible = (activity as? LifecycleOwner)
            ?.lifecycle?.currentState?.isAtLeast(Lifecycle.State.STARTED) == true
        val now = SystemClock.elapsedRealtime()
        val sinceLastRebuild = lastRebuildAt?.let { now - it }
        val rebuild = visible &&
            (sinceLastRebuild == null || sinceLastRebuild > REBUILD_COOLDOWN_MS)
        if (rebuild) {
            lastRebuildAt = now
        }

        // Off the framework's stack: let it finish burying the renderer and
        // read our `true` before the activity starts tearing itself down.
        Handler(Looper.getMainLooper()).post {
            if (activity.isFinishing || activity.isDestroyed) return@post
            if (rebuild) {
                Log.w(TAG, "rebuilding the UI")
                activity.recreate()
            } else {
                Log.w(TAG, "closing the UI; tunnel and notification stay up")
                activity.finish()
            }
        }
        return true
    }

    /** wry hands the activity itself to the webview; unwrap anyway. */
    private fun activityOf(context: Context): Activity? {
        var current: Context? = context
        while (current is ContextWrapper) {
            if (current is Activity) return current
            current = current.baseContext
        }
        return null
    }
}
