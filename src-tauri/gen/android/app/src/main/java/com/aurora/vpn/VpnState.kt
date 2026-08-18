package com.aurora.vpn

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Shared state between the Tauri plugin (driven by Rust) and the VpnService.
 * Both live in the same process; this object is the only channel they need.
 */
object VpnState {
    /** libbox `Setup` must run exactly once per process. */
    val libboxReady = AtomicBoolean(false)

    @Volatile var running = false
    @Volatile var lastError = ""

    /** The live service instance, when the tunnel is up or coming up. */
    @Volatile var service: AuroraVpnService? = null

    /**
     * One-shot completion for a pending `start` command: called with `null`
     * once libbox is up, or with an error message when it refused the config.
     */
    @Volatile var startCallback: ((String?) -> Unit)? = null

    fun finishStart(error: String?) {
        val callback = startCallback
        startCallback = null
        callback?.invoke(error)
    }
}
