package com.example.sshtunnel.vpn

import android.net.Network
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import com.example.sshtunnel.core.FatalTunnelException
import com.example.sshtunnel.core.HostKeyException
import com.example.sshtunnel.core.Socks5Server
import com.example.sshtunnel.core.SshEngine
import com.example.sshtunnel.core.Traffic
import com.example.sshtunnel.core.TunnelError
import com.example.sshtunnel.core.TunnelManager
import com.example.sshtunnel.core.TunnelState
import com.example.sshtunnel.data.SshProfile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Satu sesi tunnel dari tombol "Sambung" sampai "Putus":
 *
 *   aplikasi -> TUN -> tun2socks -> SOCKS5 lokal (127.0.0.1, auth acak) -> SSH direct-tcpip -> server
 *
 * Urutan start: SSH dulu, baru TUN. Jadi kalau server/login bermasalah, tidak ada VPN yang menggantung
 * dan lalu lintas pengguna tidak terblokir.
 *
 * Saat SSH putus atau jaringan berganti: TUN dan port SOCKS lokal TETAP hidup, hanya koneksi SSH
 * yang diganti. Selama itu koneksi baru ditolak cepat (tidak ada kebocoran ke jaringan langsung).
 */
class TunnelSession(
    private val service: TunnelVpnService,
    private val profile: SshProfile,
) {
    @Volatile
    private var engine: SshEngine? = null

    @Volatile
    private var pendingEngine: SshEngine? = null

    @Volatile
    private var established = false

    @Volatile
    private var lastNetwork: Network? = null

    private val networkChanged = AtomicBoolean(false)
    private var watcher: NetworkWatcher? = null
    private var connectedSince = 0L

    /** Menutup apa pun yang sedang memblokir (connect SSH yang menggantung). Aman dipanggil dari thread mana pun. */
    fun abort() {
        engine?.close()
        pendingEngine?.close()
    }

    suspend fun run() {
        var socks: Socks5Server? = null
        var tun: ParcelFileDescriptor? = null
        var tunnelStarted = false
        try {
            TunnelManager.setTraffic(Traffic())
            TunnelManager.setState(TunnelState.Connecting("Menghubungkan ke ${profile.host}"))

            watcher = NetworkWatcher(service, ::onNetwork).also { it.start() }
            connectEngine()

            // Kredensial acak per sesi: mencegah aplikasi lain menumpang tunnel lewat port lokal.
            val user = randomToken(12)
            val pass = randomToken(24)
            socks = Socks5Server(
                username = user,
                password = pass,
                connector = { engine },
                dnsServer = { profile.dnsServer },
                log = ::log,
            ).also { it.start() }

            TunnelManager.setState(TunnelState.Connecting("Membuat antarmuka VPN"))
            tun = establishVpn()
            tunnelStarted = Tun2Socks.start(service, tun.fd, MTU, socks.port, user, pass)
            if (!tunnelStarted) throw FatalTunnelException("Gagal memulai tun2socks (library native)")

            established = true
            lastNetwork?.let { service.setUnderlyingNetworks(arrayOf(it)) }
            connectedSince = System.currentTimeMillis()
            TunnelManager.setState(TunnelState.Connected(profile.displayName, connectedSince))
            log("Tunnel aktif")

            coroutineScope {
                launch { statsLoop() }
                superviseLoop() // berjalan sampai dibatalkan atau terjadi kesalahan fatal
            }
        } catch (e: CancellationException) {
            TunnelManager.setState(TunnelState.Disconnected)
            throw e
        } catch (e: Throwable) {
            log("Gagal: ${e.message ?: e.javaClass.simpleName}")
            TunnelManager.setState(TunnelState.Failed(profile.id, toTunnelError(e)))
        } finally {
            withContext(NonCancellable + Dispatchers.IO) {
                established = false
                watcher?.stop()
                if (tunnelStarted) Tun2Socks.stop() // berhenti memakai SOCKS dan fd TUN dulu
                tun?.close()
                socks?.close()
                engine?.close()
                pendingEngine?.close()
                engine = null
                log("Tunnel dihentikan")
            }
        }
    }

    // ---------------------------------------------------------------- supervisi

    private suspend fun superviseLoop() {
        while (true) {
            delay(SUPERVISE_INTERVAL_MS)
            val reason = when {
                networkChanged.getAndSet(false) -> "jaringan berubah"
                engine?.isAlive() != true -> "koneksi SSH terputus"
                else -> continue
            }
            reconnect(reason)
        }
    }

    private suspend fun reconnect(reason: String) {
        log("Menyambung ulang: $reason")
        val old = engine
        engine = null // SOCKS menolak koneksi baru sampai SSH baru siap
        old?.close()
        var attempt = 0
        var backoff = INITIAL_BACKOFF_MS
        while (true) {
            if (watcher?.current == null) {
                TunnelManager.setState(TunnelState.Reconnecting(attempt, "menunggu jaringan"))
                delay(SUPERVISE_INTERVAL_MS)
                continue
            }
            attempt++
            TunnelManager.setState(TunnelState.Reconnecting(attempt, reason))
            try {
                connectEngine()
                TunnelManager.setState(TunnelState.Connected(profile.displayName, connectedSince))
                log("Tersambung kembali")
                return
            } catch (e: CancellationException) {
                throw e
            } catch (e: HostKeyException) {
                throw e
            } catch (e: FatalTunnelException) {
                throw e
            } catch (e: IOException) {
                log("Percobaan $attempt gagal: ${e.message}")
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
            }
        }
    }

    private suspend fun connectEngine() {
        val candidate = SshEngine(profile, protect = { service.protect(it) }, log = ::log)
        pendingEngine = candidate
        try {
            withContext(Dispatchers.IO) { candidate.connect() }
            engine = candidate
        } finally {
            pendingEngine = null
        }
    }

    private fun onNetwork(network: Network?) {
        if (network == null) {
            log("Jaringan hilang")
            if (established) networkChanged.set(true)
            return
        }
        val previous = lastNetwork
        lastNetwork = network
        if (!established) return
        runCatching { service.setUnderlyingNetworks(arrayOf(network)) }
        if (previous != null && previous != network) {
            log("Jaringan berganti")
            networkChanged.set(true)
        }
    }

    private suspend fun statsLoop() {
        var previous: LongArray? = null
        var previousAt = SystemClock.elapsedRealtime()
        while (true) {
            delay(1_000)
            val now = Tun2Socks.stats() ?: continue
            val at = SystemClock.elapsedRealtime()
            val seconds = ((at - previousAt).coerceAtLeast(1)) / 1000.0
            val download = now[STAT_RX_BYTES]
            val upload = now[STAT_TX_BYTES]
            val before = previous
            TunnelManager.setTraffic(
                Traffic(
                    downloadBytes = download,
                    uploadBytes = upload,
                    downloadRate = if (before == null) 0 else ((download - before[STAT_RX_BYTES]) / seconds).toLong(),
                    uploadRate = if (before == null) 0 else ((upload - before[STAT_TX_BYTES]) / seconds).toLong(),
                ),
            )
            previous = now
            previousAt = at
        }
    }

    // ---------------------------------------------------------------- VPN

    private fun establishVpn(): ParcelFileDescriptor {
        // Resolver yang "dilihat" aplikasi. Isinya tidak penting: semua query UDP port 53 dialihkan
        // oleh Socks5Server ke profile.dnsServer lewat tunnel. Pakai alamat profil bila berupa IPv4.
        val appDns = if (IPV4.matches(profile.dnsServer)) profile.dnsServer else "8.8.8.8"

        val builder = service.newBuilder()
            .setSession(profile.displayName)
            .setMtu(MTU)
            .addAddress(DEVICE_V4, 30)
            .addRoute("0.0.0.0", 0)
            .addAddress(DEVICE_V6, 126)
            .addRoute("::", 0) // IPv6 ikut masuk tunnel, tidak bocor lewat jaringan langsung
            .addDnsServer(appDns)
        try {
            // Aplikasi ini sendiri (koneksi SSH) tidak boleh masuk ke tunnel-nya sendiri.
            builder.addDisallowedApplication(service.packageName)
        } catch (e: Exception) {
            log("Peringatan: gagal mengecualikan aplikasi dari VPN (${e.message})")
        }
        return builder.establish()
            ?: throw FatalTunnelException("Izin VPN tidak diberikan atau sudah dicabut")
    }

    // ---------------------------------------------------------------- util

    private fun toTunnelError(e: Throwable): TunnelError = when (e) {
        is HostKeyException -> e.error
        else -> TunnelError.Message(e.message ?: e.javaClass.simpleName)
    }

    private fun log(message: String) = TunnelManager.log(message)

    private fun randomToken(length: Int): String {
        val random = SecureRandom()
        return String(CharArray(length) { TOKEN_ALPHABET[random.nextInt(TOKEN_ALPHABET.length)] })
    }

    private companion object {
        const val MTU = 1500
        const val DEVICE_V4 = "198.18.0.2" // satu blok /30 dengan Tun2Socks.GATEWAY_V4 (198.18.0.1)
        const val DEVICE_V6 = "fc00::2" // satu blok /126 dengan Tun2Socks.GATEWAY_V6 (fc00::1)
        const val SUPERVISE_INTERVAL_MS = 1_000L
        const val INITIAL_BACKOFF_MS = 1_000L
        const val MAX_BACKOFF_MS = 30_000L
        const val STAT_TX_BYTES = 1
        const val STAT_RX_BYTES = 3
        const val TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    }
}
