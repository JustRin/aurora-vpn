package com.aurora.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  /** Set only while the teardown asks whether the activity is coming back. */
  private var claimRecreation = false

  // The app's own result launchers, registered by every activity in its own
  // constructor — where androidx requires them — because Tauri's cannot be:
  // `PluginManager.onActivityCreate` returns early once it holds an activity,
  // so the launchers it registers stay bound to the first one, and androidx
  // unregisters those the moment that activity is destroyed. Launching through
  // them after a recreation throws instead of showing a dialog, which is a
  // hang for whoever is waiting on the answer.

  private val consentLauncher = registerForActivityResult(
    ActivityResultContracts.StartActivityForResult(),
  ) { result ->
    VpnState.finishConsent(result.resultCode == Activity.RESULT_OK)
  }

  private val notificationLauncher = registerForActivityResult(
    ActivityResultContracts.RequestPermission(),
  ) { granted ->
    Log.i(TAG, "notification permission granted: $granted")
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    // wry files the state it needs to rebuild the webview under the activity's
    // id, and an activity started from scratch invents a fresh one
    // (`hashCode()`) unless the id is handed to it — a task swiped out of
    // Recents leaves no saved state to carry it. Hand back the id of the
    // activity this one replaces, so the rebuild below finds its state.
    lastActivityId?.let { intent.putExtra(WRY_ACTIVITY_ID, it) }
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    lastActivityId = id
    // From here on the consent flow reaches this activity rather than the one
    // Tauri handed the plugin at startup and never swapped.
    VpnState.bindActivity(this)
    // Edge-to-edge is enforced from targetSdk 35, and the WebView cannot see
    // the bar sizes itself (env(safe-area-inset-*) stays 0 in Android's
    // WebView), so the native content view takes the insets as padding: the
    // page starts below the status bar, ends above the gesture bar, and the
    // keyboard (ime) never covers an input. The uncovered strips show the
    // theme's windowBackground, which matches the web app's background.
    val content = findViewById<android.view.View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { v, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars()
          or WindowInsetsCompat.Type.displayCutout()
          or WindowInsetsCompat.Type.ime()
      )
      v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      WindowInsetsCompat.CONSUMED
    }
    handleLaunchIntent(intent)
  }

  /** `singleTask`: a widget or tile opening the running app lands here. */
  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleLaunchIntent(intent)
  }

  /**
   * Besides clearing the error a widget opened the app for, this answers a
   * consent request whose result never came. The system dialog can outlive
   * the activity that opened it — with "don't keep activities" on, opening it
   * destroys us, and the result is delivered, if at all, to whatever replaced
   * us — and a background activity start can be dropped so that it never opens
   * in the first place. Neither leaves anything to wait for, and
   * `VpnService.prepare` is the same question the dialog asks, so ask it.
   *
   * Unconditional on purpose: a result that did arrive got here first — pending
   * results are delivered before `onResume`, and one restored along with a
   * recreated activity is dispatched on ON_START — so there is nothing left
   * pending in the cases that worked.
   */
  override fun onResume() {
    super.onResume()
    // Opening the app answers whatever the service could not do alone —
    // a widget showing «open the app» has been obeyed.
    if (VpnState.lastError.isNotEmpty() && VpnState.phase == Phase.IDLE) {
      VpnState.lastError = ""
      VpnState.lastErrorHint = 0
      TunnelBus.changed(this)
    }
    if (VpnState.consentPending) {
      VpnState.finishConsent(VpnService.prepare(this) == null)
    }
  }

  /**
   * A widget or the tile wanted a connection the service could not make on
   * its own (VPN consent still to be granted, or no config yet) and opened
   * the app for it. The request goes to Rust — right away if its runtime is
   * up, otherwise the moment it subscribes. The extra is cleared so an
   * activity recreated from this intent does not connect again.
   */
  private fun handleLaunchIntent(intent: Intent?) {
    if (intent?.getBooleanExtra(EXTRA_CONNECT, false) != true) return
    intent.removeExtra(EXTRA_CONNECT)
    VpnState.requestConnect()
  }

  /** Show the system VPN-consent dialog; the answer lands in [VpnState]. */
  fun requestVpnConsent(intent: Intent) {
    try {
      consentLauncher.launch(intent)
    } catch (e: Exception) {
      // No dialog means no result, ever, and this activity is the one already
      // on screen — there is no resume coming to fall back on. Answer now: a
      // refusal the user can act on beats a `prepare` that never returns.
      Log.e(TAG, "VPN consent dialog: ${e.message}")
      VpnState.finishConsent(false)
    }
  }

  /** Cosmetic — the tunnel runs whether or not notifications are allowed. */
  fun requestNotificationPermission() {
    try {
      notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    } catch (e: Exception) {
      Log.w(TAG, "notification permission prompt skipped: ${e.message}")
    }
  }

  /**
   * Both halves of the Rust runtime — tao's window and wry's webview — throw
   * their state away on destroy unless the activity says it is coming back,
   * and this is the only thing they ask. Normally that is right: the process
   * dies with the activity anyway. Here it is not. The tunnel runs in a
   * foreground service, so the process outlives an activity that Android
   * destroys on its own — task swiped away, background memory trim — while
   * `main()` runs exactly once per process and never rebuilds anything. The
   * next launch would then attach an activity to a runtime that has forgotten
   * how to draw: no content view, just the theme's background colour.
   *
   * Claiming the recreation keeps that state alive, and the next
   * `onActivityCreate` puts the webview back from it. Cost of claiming it
   * wrongly, when nothing comes back: one destroyed activity and its webview
   * held until the process ends, and ViewModels (the app has none) not
   * cleared — against a window that never draws again.
   */
  override fun isChangingConfigurations(): Boolean =
    claimRecreation || super.isChangingConfigurations()

  override fun onDestroy() {
    VpnState.unbindActivity(this)
    claimRecreation = true
    // This is what calls Rust.onActivityDestroy and Rust.onWebviewDestroy.
    super.onDestroy()
    claimRecreation = false
  }

  companion object {
    /** Boolean extra: connect as soon as the Rust runtime is listening. */
    const val EXTRA_CONNECT = "com.aurora.vpn.extra.CONNECT"

    private const val TAG = "MainActivity"

    /** `WryActivity`'s own key for the id, private there and mirrored here. */
    private const val WRY_ACTIVITY_ID = "__wryActivityId"

    /** Survives the activity, not the process — exactly the lifetime wanted. */
    @Volatile
    private var lastActivityId: Int? = null
  }
}
