package com.aurora.vpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import android.util.SizeF
import android.view.View
import android.widget.RemoteViews

private const val TAG = "AuroraWidget"

/** What a widget shows, distilled from the service's phase and Rust's view. */
enum class WidgetState { OFF, CONNECTING, ON, NO_LINK, ERROR }

/**
 * The service's phase decides whether the tunnel exists; Rust, when it is up,
 * refines that into «still connecting» or «the server stopped answering».
 * Rust's view can lag by a second after a widget click — the phase wins.
 */
fun currentWidgetState(): WidgetState {
    val rust = VpnState.rust
    return when (VpnState.phase) {
        Phase.STARTING -> WidgetState.CONNECTING
        Phase.RUNNING -> when {
            rust.state == "connecting" -> WidgetState.CONNECTING
            rust.state == "connected" && rust.link == "down" -> WidgetState.NO_LINK
            else -> WidgetState.ON
        }
        Phase.IDLE ->
            if (VpnState.lastError.isNotEmpty() || rust.state == "error") WidgetState.ERROR
            else WidgetState.OFF
    }
}

/**
 * Three entries in the launcher's widget picker. They differ in default size
 * and preview only: the drawing is shared and follows the actual size, so a
 * «status» widget stretched to four cells shows everything the «traffic» one
 * does.
 */
enum class WidgetKind { TOGGLE, COMPACT, FULL }

class ToggleWidget : AuroraWidget(WidgetKind.TOGGLE)
class CompactWidget : AuroraWidget(WidgetKind.COMPACT)
class FullWidget : AuroraWidget(WidgetKind.FULL)

abstract class AuroraWidget(private val kind: WidgetKind) : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        for (id in ids) WidgetUpdater.render(context, manager, id, kind)
    }

    override fun onAppWidgetOptionsChanged(
        context: Context,
        manager: AppWidgetManager,
        id: Int,
        options: Bundle,
    ) {
        WidgetUpdater.render(context, manager, id, kind)
    }

    override fun onEnabled(context: Context) = TunnelBus.widgetsChanged(context)

    override fun onDisabled(context: Context) = TunnelBus.widgetsChanged(context)

    override fun onDeleted(context: Context, ids: IntArray) = TunnelBus.widgetsChanged(context)
}

object WidgetUpdater {
    private val PROVIDERS = mapOf(
        WidgetKind.TOGGLE to ToggleWidget::class.java,
        WidgetKind.COMPACT to CompactWidget::class.java,
        WidgetKind.FULL to FullWidget::class.java,
    )

    /** The toggle never shows numbers; the other two always can. */
    private val TRAFFIC_KINDS = listOf(WidgetKind.COMPACT, WidgetKind.FULL)

    private fun ids(context: Context, manager: AppWidgetManager, kind: WidgetKind): IntArray =
        try {
            manager.getAppWidgetIds(ComponentName(context, PROVIDERS.getValue(kind)))
        } catch (_: Exception) {
            IntArray(0)
        }

    fun updateAll(context: Context) {
        val manager = AppWidgetManager.getInstance(context) ?: return
        for (kind in PROVIDERS.keys) {
            for (id in ids(context, manager, kind)) render(context, manager, id, kind)
        }
    }

    fun updateTraffic(context: Context) {
        val manager = AppWidgetManager.getInstance(context) ?: return
        for (kind in TRAFFIC_KINDS) {
            for (id in ids(context, manager, kind)) render(context, manager, id, kind)
        }
    }

    /** Whether anything on the home screen would show a traffic sample. */
    fun wantsTraffic(context: Context): Boolean {
        val manager = AppWidgetManager.getInstance(context) ?: return false
        return TRAFFIC_KINDS.any { ids(context, manager, it).isNotEmpty() }
    }

    fun render(context: Context, manager: AppWidgetManager, id: Int, kind: WidgetKind) {
        try {
            manager.updateAppWidget(id, WidgetRenderer.build(context, manager, id, kind))
        } catch (e: Exception) {
            Log.w(TAG, "update $id: ${e.message}")
        }
    }
}

/**
 * Builds the RemoteViews. Four layouts cover every size a widget can take:
 * one and two rows, each narrow (two or three cells) and wide (four or more).
 * On Android 12+ all four are handed over at once and the launcher picks per
 * actual size; older launchers get the one matching the widget's minimum.
 */
object WidgetRenderer {
    /** Android sizes cells as 70·n − 30 dp: four cells begin at 250. */
    private const val WIDE_DP = 250f

    /** Narrow layouts fit any height; the two-row ones need this much. */
    private const val TALL_DP = 120f

    private const val REQ_OPEN = 10
    private const val REQ_OPEN_CONNECT = 11
    private const val REQ_TOGGLE = 12

    fun build(context: Context, manager: AppWidgetManager, id: Int, kind: WidgetKind): RemoteViews {
        if (kind == WidgetKind.TOGGLE) return toggle(context)

        if (Build.VERSION.SDK_INT >= 31) {
            return RemoteViews(
                mapOf(
                    SizeF(110f, 40f) to compact(context, tall = false),
                    SizeF(WIDE_DP, 40f) to full(context, row = true),
                    SizeF(110f, TALL_DP) to compact(context, tall = true),
                    SizeF(WIDE_DP, TALL_DP) to full(context, row = false),
                ),
            )
        }

        val options = manager.getAppWidgetOptions(id)
        val minWidth = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH)
        val minHeight = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT)
        val wide = minWidth >= WIDE_DP
        val tall = minHeight >= TALL_DP
        return if (wide) full(context, row = !tall) else compact(context, tall)
    }

    private fun toggle(context: Context): RemoteViews =
        RemoteViews(context.packageName, R.layout.widget_toggle).also { bindButton(context, it) }

    private fun compact(context: Context, tall: Boolean): RemoteViews {
        val layout = if (tall) R.layout.widget_compact_tall else R.layout.widget_compact
        return RemoteViews(context.packageName, layout).also {
            bindButton(context, it)
            bindStatus(context, it)
            bindSpeeds(context, it)
            it.setOnClickPendingIntent(R.id.root, openApp(context))
        }
    }

    private fun full(context: Context, row: Boolean): RemoteViews {
        val layout = if (row) R.layout.widget_full_row else R.layout.widget_full
        return RemoteViews(context.packageName, layout).also {
            bindButton(context, it)
            bindStatus(context, it)
            bindSpeeds(context, it)
            if (!row) bindTotals(context, it)
            it.setOnClickPendingIntent(R.id.root, openApp(context))
        }
    }

    // ------------------------------------------------------------- pieces

    private fun bindButton(context: Context, views: RemoteViews) {
        val state = currentWidgetState()
        val background = when (state) {
            WidgetState.ON -> R.drawable.widget_btn_on
            WidgetState.CONNECTING, WidgetState.NO_LINK -> R.drawable.widget_btn_busy
            WidgetState.ERROR -> R.drawable.widget_btn_error
            WidgetState.OFF -> R.drawable.widget_btn_off
        }
        views.setInt(R.id.btn, "setBackgroundResource", background)
        val icon = if (state == WidgetState.OFF) context.getColor(R.color.widget_icon_off) else 0xFFFFFFFF.toInt()
        views.setInt(R.id.btn, "setColorFilter", icon)
        views.setContentDescription(R.id.btn, context.getString(stateLabel(state)))
        views.setOnClickPendingIntent(R.id.btn, toggleIntent(context))
    }

    private fun bindStatus(context: Context, views: RemoteViews) {
        val state = currentWidgetState()
        views.setTextViewText(R.id.state, context.getString(stateLabel(state)))
        views.setInt(R.id.state_dot, "setColorFilter", stateColor(context, state))
        views.setTextViewText(R.id.server, serverLine(context, state))
    }

    private fun bindSpeeds(context: Context, views: RemoteViews) {
        val running = VpnState.phase == Phase.RUNNING
        views.setViewVisibility(R.id.traffic, if (running) View.VISIBLE else View.GONE)
        if (!running) return
        val traffic = VpnState.traffic
        views.setTextViewText(R.id.down_speed, Fmt.speed(context, traffic.downSpeed))
        views.setTextViewText(R.id.up_speed, Fmt.speed(context, traffic.upSpeed))
    }

    private fun bindTotals(context: Context, views: RemoteViews) {
        val running = VpnState.phase == Phase.RUNNING
        views.setViewVisibility(R.id.totals, if (running) View.VISIBLE else View.GONE)
        if (!running) {
            views.setChronometer(R.id.uptime, SystemClock.elapsedRealtime(), null, false)
            return
        }
        val traffic = VpnState.traffic
        views.setTextViewText(R.id.down_total, Fmt.bytes(context, traffic.downTotal))
        views.setTextViewText(R.id.up_total, Fmt.bytes(context, traffic.upTotal))
        // The clock ticks in the launcher on its own — no update per second needed.
        views.setChronometer(R.id.uptime, VpnState.startedAtElapsed, null, true)
    }

    private fun stateLabel(state: WidgetState): Int = when (state) {
        WidgetState.OFF -> R.string.widget_state_off
        WidgetState.CONNECTING -> R.string.widget_state_connecting
        WidgetState.ON -> R.string.widget_state_on
        WidgetState.NO_LINK -> R.string.widget_state_no_link
        WidgetState.ERROR -> R.string.widget_state_error
    }

    private fun stateColor(context: Context, state: WidgetState): Int = context.getColor(
        when (state) {
            WidgetState.OFF -> R.color.widget_text_dim
            WidgetState.CONNECTING, WidgetState.NO_LINK -> R.color.widget_busy
            WidgetState.ON -> R.color.widget_ok
            WidgetState.ERROR -> R.color.widget_error
        },
    )

    /** Second line: the server, or what stands in its way. */
    private fun serverLine(context: Context, state: WidgetState): String {
        if (state == WidgetState.ERROR) {
            val hint = VpnState.lastErrorHint
            return if (hint != 0) context.getString(hint) else context.getString(R.string.widget_err_generic)
        }
        val name = TunnelControl.serverLabel(context)
        if (name.isNotEmpty()) return name
        return context.getString(
            if (state == WidgetState.OFF) R.string.widget_tap_to_connect else R.string.widget_no_server,
        )
    }

    // ------------------------------------------------------------ intents

    private val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    private fun openApp(context: Context): PendingIntent =
        PendingIntent.getActivity(context, REQ_OPEN, TunnelControl.openAppIntent(context, false), flags)

    /**
     * The button. Straight to the service whenever it can act alone — a stop
     * always can, a start needs consent and a config; otherwise the app opens
     * and connects itself, consent dialog included. A widget tap counts as a
     * user interaction, which is what lets the foreground start through on
     * Android 12+.
     */
    private fun toggleIntent(context: Context): PendingIntent {
        val direct = VpnState.phase != Phase.IDLE || TunnelControl.canStartSilently(context)
        if (!direct) {
            return PendingIntent.getActivity(
                context, REQ_OPEN_CONNECT, TunnelControl.openAppIntent(context, true), flags,
            )
        }
        val intent = TunnelControl.serviceIntent(context, AuroraVpnService.ACTION_TOGGLE)
        return if (Build.VERSION.SDK_INT >= 26) {
            PendingIntent.getForegroundService(context, REQ_TOGGLE, intent, flags)
        } else {
            PendingIntent.getService(context, REQ_TOGGLE, intent, flags)
        }
    }
}
