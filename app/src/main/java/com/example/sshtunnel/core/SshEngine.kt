package com.example.sshtunnel.core

import android.util.Base64
import com.example.sshtunnel.data.AuthType
import com.example.sshtunnel.data.SshProfile
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.Factory
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.transport.compression.Compression
import net.schmizz.sshj.transport.compression.DelayedZlibCompression
import net.schmizz.sshj.transport.compression.NoneCompression
import net.schmizz.sshj.transport.compression.ZlibCompression
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.method.PasswordResponseProvider
import net.schmizz.sshj.userauth.password.PasswordUtils
import java.io.Closeable
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.PublicKey
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory

/**
 * Satu sesi koneksi SSH ke server. Pemakaian:
 * [connect] (memblokir, panggil dari thread IO) -> [openDirect] dipakai SOCKS5 ->
 * [isAlive] untuk mendeteksi putus -> [close]. Satu objek hanya untuk satu kali [connect].
 */
class SshEngine(
    private val profile: SshProfile,
    private val protect: (Socket) -> Boolean,
    private val log: (String) -> Unit,
) : SshConnector {

    @Volatile
    private var client: SSHClient? = null

    /** Klien yang sedang handshake; disimpan supaya [close] bisa membatalkan connect yang masih berjalan. */
    @Volatile
    private var pending: SSHClient? = null

    @Volatile
    private var closed = false

    /**
     * Terhubung, memverifikasi host key, login, dan memastikan server mengizinkan forwarding.
     * @throws HostKeyException host key belum dipercaya / berubah
     * @throws FatalTunnelException kesalahan permanen (login ditolak, forwarding dilarang)
     * @throws IOException kesalahan jaringan (boleh dicoba ulang)
     */
    fun connect() {
        val verifier = PinnedHostKeyVerifier(profile.trustedHostKey)

        val config = DefaultConfig()
        if (profile.compression) {
            config.compressionFactories = listOf<Factory.Named<Compression>>(
                DelayedZlibCompression.Factory(),
                ZlibCompression.Factory(),
                NoneCompression.Factory(),
            )
        }
        val ssh = SSHClient(config)
        // Sengaja tidak memakai ssh.timeout: itu menjadi SO_TIMEOUT dan akan memutus koneksi yang sedang idle.
        ssh.connectTimeout = CONNECT_TIMEOUT_MS
        ssh.socketFactory = ProtectingSocketFactory(protect)
        ssh.addHostKeyVerifier(verifier)
        pending = ssh
        if (closed) {
            closeQuietly(ssh)
            throw IOException("Dibatalkan")
        }

        val timedOut = AtomicBoolean(false)
        val watchdog = Timers.schedule(HANDSHAKE_TIMEOUT_MS) {
            timedOut.set(true)
            closeQuietly(ssh)
        }
        try {
            log("Menghubungkan ke ${profile.host}:${profile.port} ...")
            try {
                ssh.connect(profile.host, profile.port)
            } catch (e: IOException) {
                verifier.error?.let { throw HostKeyException(it) }
                throw e
            }
            log("Host key cocok, login sebagai ${profile.username} ...")
            authenticate(ssh)
            ssh.connection.keepAlive.keepAliveInterval = profile.keepAliveSeconds
            checkForwardingAllowed(ssh)
        } catch (t: Throwable) {
            closeQuietly(ssh)
            throw translate(t, timedOut.get())
        } finally {
            watchdog.cancel(false)
            pending = null
        }
        if (closed) { // close() dipanggil saat handshake
            closeQuietly(ssh)
            throw IOException("Dibatalkan")
        }
        client = ssh
        log("SSH tersambung")
    }

    private fun authenticate(ssh: SSHClient) {
        when (profile.authType) {
            AuthType.PASSWORD -> try {
                ssh.authPassword(profile.username, profile.password)
            } catch (e: UserAuthException) {
                // Sebagian server hanya menawarkan keyboard-interactive untuk login password.
                try {
                    ssh.authKeyboardInteractive(
                        profile.username,
                        PasswordResponseProvider(PasswordUtils.createOneOff(profile.password.toCharArray())),
                    )
                } catch (_: UserAuthException) {
                    throw e
                }
            }

            AuthType.PRIVATE_KEY -> {
                val finder = profile.keyPassphrase.takeIf { it.isNotEmpty() }
                    ?.let { PasswordUtils.createOneOff(it.toCharArray()) }
                // Isi key dimuat langsung dari teks; tidak pernah ditulis ke file.
                val keys = ssh.loadKeys(profile.privateKey, null, finder)
                ssh.authPublickey(profile.username, keys)
            }
        }
    }

    /** Gagal lebih awal dengan pesan jelas jika server melarang TCP forwarding. */
    private fun checkForwardingAllowed(ssh: SSHClient) {
        try {
            ssh.newDirectConnection(profile.dnsServer, 53).close()
        } catch (e: IOException) {
            throw FatalTunnelException(
                "Server menolak membuka forwarding ke ${profile.dnsServer}:53. " +
                    "Pastikan AllowTcpForwarding aktif di sshd_config server dan DNS di profil dapat dijangkau dari server.",
                e,
            )
        }
    }

    private fun translate(t: Throwable, timedOut: Boolean): Throwable = when {
        t is HostKeyException || t is FatalTunnelException -> t
        t is UserAuthException ->
            FatalTunnelException("Login ditolak server (username/password/key salah, atau metode tidak diizinkan)", t)
        timedOut -> IOException("Waktu habis saat handshake SSH (server tidak merespons)", t)
        t is UnknownHostException -> IOException("Host tidak ditemukan: ${profile.host}", t)
        t is ConnectException -> IOException("Tidak bisa terhubung ke ${profile.host}:${profile.port} (${t.message})", t)
        t is NoRouteToHostException -> IOException("Tidak ada rute ke ${profile.host}", t)
        t is SocketTimeoutException -> IOException("Waktu koneksi habis", t)
        t is IOException -> t
        else -> IOException(t.message ?: t.javaClass.simpleName, t)
    }

    override fun openDirect(host: String, port: Int): DuplexChannel {
        val ssh = client ?: throw IOException("SSH tidak tersambung")
        val connection = ssh.newDirectConnection(host, port)
        return object : DuplexChannel {
            override val input = connection.inputStream
            override val output = connection.outputStream
            override fun close() {
                closeQuietly(connection)
            }
        }
    }

    /** False jika koneksi SSH sudah putus (keepalive gagal, server menutup, jaringan hilang). */
    fun isAlive(): Boolean {
        val ssh = client ?: return false
        return ssh.isConnected && ssh.isAuthenticated && ssh.transport.isRunning
    }

    fun close() {
        closed = true
        val ssh = client
        client = null
        closeQuietly(ssh)
        closeQuietly(pending)
    }

    private fun closeQuietly(c: Closeable?) {
        try {
            c?.close()
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000
        const val HANDSHAKE_TIMEOUT_MS = 30_000L
    }
}

/** Menerima host key hanya jika fingerprint SHA-256-nya sama dengan yang sudah dipercaya pengguna. */
class PinnedHostKeyVerifier(private val trusted: String) : HostKeyVerifier {
    @Volatile
    var error: TunnelError? = null
        private set

    override fun verify(hostname: String, port: Int, key: PublicKey): Boolean {
        val fingerprint = fingerprintSha256(key)
        if (trusted.isNotBlank() && trusted == fingerprint) return true
        error = if (trusted.isBlank()) {
            TunnelError.HostKeyUnknown(KeyType.fromKey(key).toString(), fingerprint)
        } else {
            TunnelError.HostKeyChanged(expected = trusted, actual = fingerprint)
        }
        return false
    }

    override fun findExistingAlgorithms(hostname: String, port: Int): List<String> = emptyList()

    companion object {
        /** Format sama dengan `ssh-keygen -l`: "SHA256:" + Base64 tanpa padding. */
        fun fingerprintSha256(key: PublicKey): String {
            val blob = Buffer.PlainBuffer().putPublicKey(key).compactData
            val digest = MessageDigest.getInstance("SHA-256").digest(blob)
            return "SHA256:" + Base64.encodeToString(digest, Base64.NO_WRAP or Base64.NO_PADDING)
        }
    }
}

/** Membuat socket yang dikecualikan dari VPN (VpnService.protect) agar SSH tidak masuk ke tunnel-nya sendiri. */
class ProtectingSocketFactory(private val protect: (Socket) -> Boolean) : SocketFactory() {
    override fun createSocket(): Socket = Socket().also {
        try {
            protect(it)
        } catch (_: Exception) {
            // Aplikasi ini juga dikecualikan lewat addDisallowedApplication, jadi aman jika gagal.
        }
    }

    override fun createSocket(host: String, port: Int): Socket =
        createSocket().also { it.connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        createSocket().also {
            it.bind(InetSocketAddress(localHost, localPort))
            it.connect(InetSocketAddress(host, port))
        }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        createSocket().also { it.connect(InetSocketAddress(host, port)) }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        createSocket().also {
            it.bind(InetSocketAddress(localAddress, localPort))
            it.connect(InetSocketAddress(address, port))
        }
}
