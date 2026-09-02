package com.aurora.vpn

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * The quick-settings tile: one tap connects with the last config or
 * disconnects. Lives in the app process next to the service, so a stop is a
 * plain call and a start is a foreground-service start the system treats as
 * user-driven. What the service cannot do alone — the VPN consent dialog,
 * a first connection with no config — is handed to the app.
 */
class AuroraTileService : TileService() {

    override fun onStartListening() {
        render()
    }

    override fun onClick() {
        if (VpnState.phase == Phase.IDLE) {
            if (!TunnelControl.start(this)) openApp()
        } else if (isLocked) {
            // Anyone can turn a VPN on from the lock screen; turning it off
            // stays with whoever can unlock the phone.
            unlockAndRun {
                TunnelControl.stop()
                render()
            }
            return
        } else {
            TunnelControl.stop()
        }
        render()
    }

    private fun openApp() {
        val intent = TunnelControl.openAppIntent(this, connect = true)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this, 0, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun render() {
        val tile = qsTile ?: return
        val state = currentWidgetState()
        tile.state = when (state) {
            WidgetState.ON, WidgetState.NO_LINK, WidgetState.CONNECTING -> Tile.STATE_ACTIVE
            WidgetState.OFF, WidgetState.ERROR -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.app_name)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_tile)
        val detail = when (state) {
            WidgetState.ON -> serverName()
            WidgetState.CONNECTING -> getString(R.string.widget_state_connecting)
            WidgetState.NO_LINK -> getString(R.string.widget_state_no_link)
            WidgetState.ERROR -> getString(R.string.widget_state_error)
            WidgetState.OFF -> getString(R.string.widget_state_off)
        }
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = detail
        }
        tile.contentDescription = "${tile.label}: $detail"
        tile.updateTile()
    }

    private fun serverName(): String {
        val name = TunnelControl.serverLabel(this)
        return if (name.isNotEmpty()) name else getString(R.string.widget_state_on)
    }

    companion object {
        /** Ask the system to call [onStartListening] again; a no-op while the tile is not on the panel. */
        fun refresh(context: Context) {
            try {
                requestListeningState(context, ComponentName(context, AuroraTileService::class.java))
            } catch (_: Exception) {
                // Some OEM panels throw when the tile was never added.
            }
        }
    }
}
