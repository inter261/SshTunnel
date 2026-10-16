package com.example.sshtunnel.vpn

import android.content.Context
import hev.htproxy.TProxyService
import java.io.File

/**
 * Pembungkus tipis untuk hev-socks5-tunnel (library native): membaca paket IP dari
 * file descriptor TUN, menjalankan stack TCP/IP userspace (lwIP), dan meneruskan setiap
 * koneksi ke server SOCKS5 lokal.
 *
 * Catatan perilaku (dibaca dari sumber hev-socks5-tunnel 2.19.0):
 * - TProxyStartService membuat thread sendiri dan langsung kembali.
 * - fd TUN TIDAK ditutup oleh library; pemanggil yang menutup ParcelFileDescriptor-nya.
 * - TProxyGetStats: [tx_paket, tx_byte, rx_paket, rx_byte]. "tx" = dibaca dari TUN (upload perangkat),
 *   "rx" = ditulis ke TUN (download perangkat).
 */
object Tun2Socks {
    /** Alamat "gateway" milik tun2socks; alamat perangkat ada di blok /30 yang sama (lihat TunnelSession). */
    const val GATEWAY_V4 = "198.18.0.1"
    const val GATEWAY_V6 = "fc00::1"

    private var configFile: File? = null

    fun start(context: Context, tunFd: Int, mtu: Int, socksPort: Int, username: String, password: String): Boolean {
        val file = File(context.cacheDir, "tun2socks.yml")
        file.writeText(
            """
            tunnel:
              mtu: $mtu
              ipv4: $GATEWAY_V4
              ipv6: '$GATEWAY_V6'
            socks5:
              port: $socksPort
              address: 127.0.0.1
              udp: 'udp'
              username: '$username'
              password: '$password'
            misc:
              task-stack-size: 81920
              connect-timeout: 10000
              log-level: warn
            """.trimIndent() + "\n",
        )
        // Berisi kredensial SOCKS sesi ini: hanya bisa dibaca aplikasi ini, dihapus saat stop.
        file.setReadable(false, false)
        file.setReadable(true, true)
        configFile = file
        return TProxyService.TProxyStartService(file.absolutePath, tunFd)
    }

    /** Memblokir sebentar sampai thread native berhenti. Aman dipanggil berulang. */
    fun stop() {
        try {
            TProxyService.TProxyStopService()
        } catch (_: Throwable) {
        }
        configFile?.delete()
        configFile = null
    }

    fun isRunning(): Boolean = try {
        TProxyService.TProxyIsRunning()
    } catch (_: Throwable) {
        false
    }

    /** [txPackets, txBytes, rxPackets, rxBytes] atau null jika tidak berjalan. */
    fun stats(): LongArray? = if (isRunning()) TProxyService.TProxyGetStats() else null
}
