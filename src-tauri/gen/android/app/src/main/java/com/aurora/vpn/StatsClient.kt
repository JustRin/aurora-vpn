package com.aurora.vpn

import android.util.Log
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.ConnectionEvents
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LogIterator
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import kotlin.concurrent.thread

private const val TAG = "AuroraStats"

/** Two seconds between counter samples — nanoseconds, the Go side reads a time.Duration. */
private const val STATUS_INTERVAL_NS = 2_000_000_000L

/** Reconnects after the stream drops (a reload from Rust closes it) before giving up. */
private const val MAX_RECONNECTS = 5

/**
 * Subscriber to the running box's status stream. libbox pushes the counters
 * every [STATUS_INTERVAL_NS]; each sample becomes [VpnState.traffic] and a
 * widget redraw. It also follows the selector, so a widget can name the
 * server even when the Rust runtime — which knows the pretty names — is not
 * up in this process.
 */
class StatsClient(private val service: AuroraVpnService) : CommandClientHandler {

    @Volatile
    private var closed = false

    @Volatile
    private var client: CommandClient? = null

    private var reconnects = 0

    fun start() {
        thread(name = "libbox-stats") { connectOnce() }
    }

    /**
     * Dial the command socket. `connect()` returns once the streams are up;
     * from then on libbox calls back from its own threads until the socket
     * closes, which arrives as [disconnected].
     */
    private fun connectOnce() {
        if (closed || VpnState.phase != Phase.RUNNING) return
        val options = CommandClientOptions()
        options.addCommand(Libbox.CommandStatus)
        options.addCommand(Libbox.CommandGroup)
        options.statusInterval = STATUS_INTERVAL_NS
        val client = Libbox.newCommandClient(this, options)
        this.client = client
        try {
            client.connect()
        } catch (e: Exception) {
            Log.w(TAG, "status stream: ${e.message}")
            retry()
        }
    }

    private fun retry() {
        if (closed || VpnState.phase != Phase.RUNNING || reconnects >= MAX_RECONNECTS) return
        reconnects++
        thread(name = "libbox-stats") {
            Thread.sleep(1000)
            connectOnce()
        }
    }

    fun close() {
        closed = true
        try {
            client?.disconnect()
        } catch (_: Exception) {
        }
        client = null
    }

    // ------------------------------------------------- CommandClientHandler

    override fun connected() {
        reconnects = 0
    }

    override fun disconnected(message: String?) {
        if (closed) return
        Log.d(TAG, "status stream closed: $message")
        retry()
    }

    override fun writeStatus(message: StatusMessage) {
        if (closed) return
        VpnState.traffic = Traffic(
            upSpeed = message.uplink,
            downSpeed = message.downlink,
            upTotal = message.uplinkTotal,
            downTotal = message.downlinkTotal,
            connections = message.connectionsOut,
        )
        TunnelBus.trafficTick(service)
    }

    override fun writeGroups(groups: OutboundGroupIterator) {
        if (closed) return
        // The selector names what it routes through; when that is the auto
        // group, the group itself names the node it settled on.
        val selected = HashMap<String, String>()
        while (groups.hasNext()) {
            val group = groups.next()
            selected[group.tag ?: ""] = group.selected ?: ""
        }
        var tag = selected["proxy"] ?: ""
        if (tag == "auto") {
            tag = selected["auto"] ?: tag
        }
        if (tag != VpnState.selectedTag) {
            VpnState.selectedTag = tag
            TunnelBus.changed(service)
        }
    }

    override fun clearLogs() {}

    override fun initializeClashMode(modes: StringIterator, current: String) {}

    override fun setDefaultLogLevel(level: Int) {}

    override fun updateClashMode(mode: String) {}

    override fun writeConnectionEvents(events: ConnectionEvents) {}

    override fun writeLogs(logs: LogIterator) {}
}
