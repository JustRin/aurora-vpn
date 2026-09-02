package com.aurora.vpn

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  /** Set only while the teardown asks whether the activity is coming back. */
  private var claimRecreation = false

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

  override fun onResume() {
    super.onResume()
    // Opening the app answers whatever the service could not do alone —
    // a widget showing «open the app» has been obeyed.
    if (VpnState.lastError.isNotEmpty() && VpnState.phase == Phase.IDLE) {
      VpnState.lastError = ""
      VpnState.lastErrorHint = 0
      TunnelBus.changed(this)
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
    claimRecreation = true
    // This is what calls Rust.onActivityDestroy and Rust.onWebviewDestroy.
    super.onDestroy()
    claimRecreation = false
  }

  companion object {
    /** Boolean extra: connect as soon as the Rust runtime is listening. */
    const val EXTRA_CONNECT = "com.aurora.vpn.extra.CONNECT"

    /** `WryActivity`'s own key for the id, private there and mirrored here. */
    private const val WRY_ACTIVITY_ID = "__wryActivityId"

    /** Survives the activity, not the process — exactly the lifetime wanted. */
    @Volatile
    private var lastActivityId: Int? = null
  }
}
