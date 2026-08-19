package com.aurora.vpn

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
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
  }
}
