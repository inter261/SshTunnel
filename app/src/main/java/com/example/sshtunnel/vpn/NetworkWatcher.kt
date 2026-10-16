package com.example.sshtunnel.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/**
 * Memantau jaringan default fisik (Wi-Fi/seluler) yang dipakai aplikasi ini.
 *
 * Aplikasi ini dikecualikan dari VPN-nya sendiri (addDisallowedApplication), sehingga "default network"
 * dari sudut pandang aplikasi adalah jaringan fisik, bukan interface TUN. Jaringan yang jelas-jelas
 * VPN tetap diabaikan sebagai pengaman.
 */
class NetworkWatcher(
    context: Context,
    private val onChange: (Network?) -> Unit,
) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)

    @Volatile
    var current: Network? = null
        private set

    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (isVpn(network)) return
            current = network
            onChange(network)
        }

        override fun onLost(network: Network) {
            if (network != current) return
            current = null
            onChange(null)
        }
    }

    private fun isVpn(network: Network): Boolean {
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    fun start() {
        if (registered) return
        // Callback langsung dipanggil untuk jaringan yang sedang aktif.
        cm.registerDefaultNetworkCallback(callback)
        registered = true
    }

    fun stop() {
        if (!registered) return
        registered = false
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
        }
    }
}
