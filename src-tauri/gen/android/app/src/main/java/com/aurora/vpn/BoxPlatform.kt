package com.aurora.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.InetSocketAddress
import java.net.NetworkInterface as JavaNetworkInterface
import io.nekohasekai.libbox.NetworkInterface as BoxNetworkInterface

private const val TAG = "AuroraBoxPlatform"

/** Kotlin list → gomobile string iterator. */
class StringList(private val values: List<String>) : StringIterator {
    private var index = 0
    override fun len(): Int = values.size
    override fun hasNext(): Boolean = index < values.size
    override fun next(): String = values[index++]
}

/**
 * Everything libbox asks the platform for. The half that matters is
 * [openTun] — the TUN device can only come from VpnService.Builder — and
 * [autoDetectInterfaceControl], which keeps the engine's own sockets out of
 * its own tunnel via protect().
 */
class BoxPlatform(private val service: AuroraVpnService) : PlatformInterface {

    private val connectivity =
        service.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    // ------------------------------------------------------------------ TUN

    /**
     * The live TUN interface. Android keeps it up while *any* descriptor for it
     * is open, and libbox works on a dup of what [openTun] hands back — so this
     * side has to keep its own handle and close it, or the tunnel outlives the
     * engine by the whole life of the process.
     *
     * Only ever touched through [swapTun]: libbox opens the interface on its own
     * thread while the stop path closes it from the main one, and a descriptor
     * closed twice is worse than one closed never — by then the number can
     * belong to some other file entirely.
     */
    private var tun: ParcelFileDescriptor? = null

    @Synchronized
    private fun swapTun(next: ParcelFileDescriptor?) {
        val previous = tun
        tun = next
        if (previous == null) return
        try {
            previous.close()
        } catch (e: Exception) {
            Log.w(TAG, "closeTun: ${e.message}")
        }
    }

    override fun openTun(options: TunOptions): Int {
        val builder = service.Builder()
        builder.setSession("Aurora VPN")
        builder.setMtu(options.mtu)

        val inet4 = options.inet4Address
        while (inet4.hasNext()) {
            val prefix = inet4.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }
        val inet6 = options.inet6Address
        while (inet6.hasNext()) {
            val prefix = inet6.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }

        if (options.autoRoute) {
            try {
                options.dnsServerAddress?.let { builder.addDnsServer(it.value) }
            } catch (e: Exception) {
                // No usable IPv4 range for DNS hijack; the in-config resolvers
                // still work, so this is not fatal.
                Log.w(TAG, "tun: no DNS hijack address: ${e.message}")
            }

            val route4 = options.inet4RouteRange
            while (route4.hasNext()) {
                val prefix = route4.next()
                builder.addRoute(prefix.address(), prefix.prefix())
            }
            val route6 = options.inet6RouteRange
            while (route6.hasNext()) {
                val prefix = route6.next()
                builder.addRoute(prefix.address(), prefix.prefix())
            }

            val include = options.includePackage
            while (include.hasNext()) {
                try {
                    builder.addAllowedApplication(include.next())
                } catch (_: Exception) {
                    // The package was uninstalled since the rule was written.
                }
            }
            val exclude = options.excludePackage
            while (exclude.hasNext()) {
                try {
                    builder.addDisallowedApplication(exclude.next())
                } catch (_: Exception) {
                }
            }
        }

        val pfd = builder.establish()
            ?: throw IllegalStateException("VpnService.establish() вернул null — разрешение отозвано?")

        // `establish()` has already replaced any previous interface; drop our
        // handle on the old one so a reload does not pile them up.
        swapTun(pfd)
        // Lend the descriptor instead of `detachFd()`. libbox dups whatever it
        // is given and closes only its own copy, so a detached original ends up
        // owned by nobody: the engine stops, the UI says «отключено», and the
        // interface stays up with every route still pointing into it until the
        // process dies. Keeping the handle here is what makes stopping real.
        return pfd.fd
    }

    /** Takes the interface down. Idempotent — stop and destroy both call it. */
    fun closeTun() = swapTun(null)

    override fun autoDetectInterfaceControl(fd: Int) {
        if (!service.protect(fd)) {
            throw IllegalStateException("protect() failed")
        }
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    // ------------------------------------------------------ default interface

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) {
                report(network, null, capabilities, listener)
            }

            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                report(network, properties, null, listener)
            }

            override fun onLost(network: Network) {
                listener.updateDefaultInterface("", -1, false, false)
            }
        }
        networkCallback = callback
        if (Build.VERSION.SDK_INT >= 31) {
            connectivity.registerBestMatchingNetworkCallback(
                request, callback, android.os.Handler(android.os.Looper.getMainLooper()),
            )
        } else {
            connectivity.registerNetworkCallback(request, callback)
        }
    }

    private fun report(
        network: Network,
        knownProperties: LinkProperties?,
        knownCapabilities: NetworkCapabilities?,
        listener: InterfaceUpdateListener,
    ) {
        val properties = knownProperties ?: connectivity.getLinkProperties(network) ?: return
        val name = properties.interfaceName ?: return
        val index = try {
            JavaNetworkInterface.getByName(name)?.index ?: -1
        } catch (_: Exception) {
            -1
        }
        val capabilities = knownCapabilities ?: connectivity.getNetworkCapabilities(network)
        val expensive =
            capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        listener.updateDefaultInterface(name, index, expensive, false)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        networkCallback?.let {
            try {
                connectivity.unregisterNetworkCallback(it)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        listener.updateDefaultInterface("", -1, false, false)
    }

    // ------------------------------------------------------------ interfaces

    override fun getInterfaces(): NetworkInterfaceIterator {
        val interfaces = JavaNetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        val boxed = interfaces.mapNotNull { raw ->
            try {
                BoxNetworkInterface().also { box ->
                    box.name = raw.name
                    box.index = raw.index
                    box.mtu = raw.mtu
                    // Java renders IPv6 link-local addresses with their scope
                    // attached (fe80::…%dummy0), and libbox pushes every entry
                    // straight through netip.MustParsePrefix, which panics on a
                    // zone. That panic is a Go abort(): it takes the whole
                    // process down, not just the tunnel. Strip the zone.
                    box.addresses = StringList(
                        raw.interfaceAddresses.mapNotNull { entry ->
                            entry.address.hostAddress
                                ?.substringBefore('%')
                                ?.let { "$it/${entry.networkPrefixLength}" }
                        },
                    )
                    box.flags = rawFlags(raw)
                    box.type = guessType(raw.name)
                    box.dnsServer = StringList(emptyList())
                    box.metered = false
                }
            } catch (_: Exception) {
                null
            }
        }
        return object : NetworkInterfaceIterator {
            private var index = 0
            override fun hasNext(): Boolean = index < boxed.size
            override fun next(): BoxNetworkInterface = boxed[index++]
        }
    }

    /** Unix IFF_* bits, which is what libbox's linkFlags expects. */
    private fun rawFlags(raw: JavaNetworkInterface): Int {
        var flags = 0
        if (raw.isUp) flags = flags or 0x1 or 0x40 // IFF_UP | IFF_RUNNING
        if (raw.isLoopback) flags = flags or 0x8 // IFF_LOOPBACK
        if (raw.isPointToPoint) flags = flags or 0x10 // IFF_POINTOPOINT
        if (raw.supportsMulticast()) flags = flags or 0x1000 // IFF_MULTICAST
        return flags
    }

    private fun guessType(name: String): Int = when {
        name.startsWith("wlan") || name.startsWith("ap") -> io.nekohasekai.libbox.Libbox.InterfaceTypeWIFI
        name.startsWith("rmnet") || name.startsWith("ccmni") -> io.nekohasekai.libbox.Libbox.InterfaceTypeCellular
        name.startsWith("eth") -> io.nekohasekai.libbox.Libbox.InterfaceTypeEthernet
        else -> io.nekohasekai.libbox.Libbox.InterfaceTypeOther
    }

    // ------------------------------------------------------ process matching

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < 29

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): ConnectionOwner {
        if (Build.VERSION.SDK_INT < 29) {
            throw IllegalStateException("недоступно до Android 10")
        }
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        if (uid == Process.INVALID_UID) {
            throw IllegalStateException("владелец соединения не найден")
        }
        val owner = ConnectionOwner()
        owner.userId = uid
        val packages = service.packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        owner.setAndroidPackageNames(StringList(packages))
        return owner
    }

    // ------------------------------------------------------------------ misc

    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): WIFIState? = null

    override fun systemCertificates(): StringIterator? = null

    override fun clearDNSCache() {}

    override fun sendNotification(notification: io.nekohasekai.libbox.Notification) {
        service.showRuleNotification(notification.title, notification.body)
    }
}
