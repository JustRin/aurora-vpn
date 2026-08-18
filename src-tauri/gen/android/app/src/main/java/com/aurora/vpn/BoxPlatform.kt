package com.aurora.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
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
        return pfd.detachFd()
    }

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
                    box.addresses = StringList(
                        raw.interfaceAddresses.map { "${it.address.hostAddress}/${it.networkPrefixLength}" },
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
