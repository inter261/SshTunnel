package com.example.sshtunnel.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.SocketFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Cara menjangkau server SSH, gaya "SSH Custom / HTTP Custom". Urutannya:
 *
 *   TCP ke (proxy atau server) -> [TLS dengan SNI sendiri] -> [kirim payload HTTP, baca balasan] -> SSH
 *
 * Semua tahap opsional. Tanpa satu pun tahap, ini koneksi TCP langsung biasa.
 */
data class TransportConfig(
    /** Bungkus koneksi dengan TLS (seperti stunnel). */
    val useTls: Boolean = false,
    /** Nama yang dikirim di SNI. Kosong = pakai host tujuan. */
    val sni: String = "",
    /** Teks payload (lihat [PayloadBuilder] untuk placeholder). Kosong = tidak ada payload. */
    val payload: String = "",
    /** Jika diisi, TCP dibuka ke proxy ini, bukan ke server SSH. Payload biasanya berisi CONNECT. */
    val proxyHost: String = "",
    val proxyPort: Int = 8080,
) {
    val hasProxy: Boolean get() = proxyHost.isNotBlank()
    val hasPayload: Boolean get() = payload.isNotBlank()
    val isDirect: Boolean get() = !useTls && !hasPayload && !hasProxy
}

/**
 * Mengubah template payload menjadi byte yang dikirim.
 *
 * Placeholder (tidak peka huruf besar/kecil):
 * `[host]` `[port]` `[host_port]` `[protocol]` (= HTTP/1.1), `[crlf]` `[cr]` `[lf]`,
 * `[split]` = kirim bagian berikutnya di paket TCP terpisah. Urutan escape `\r` `\n` `\t` juga dikenali,
 * dan baris baru sungguhan di kolom teks dianggap `[crlf]`.
 */
object PayloadBuilder {
    fun build(template: String, host: String, port: Int): List<ByteArray> {
        var text = template.replace("\r\n", "\n").replace("\n", "[crlf]")
        fun sub(token: String, value: String) {
            text = text.replace(Regex(Regex.escape(token), RegexOption.IGNORE_CASE)) { value }
        }
        // [host_port] harus diganti sebelum [host]
        sub("[host_port]", if (host.contains(':')) "[$host]:$port" else "$host:$port")
        sub("[host]", host)
        sub("[port]", port.toString())
        sub("[protocol]", "HTTP/1.1")
        sub("[crlf]", "\r\n")
        sub("[cr]", "\r")
        sub("[lf]", "\n")
        text = text.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t")
        return text.split(Regex(Regex.escape("[split]"), RegexOption.IGNORE_CASE))
            .filter { it.isNotEmpty() }
            .map { it.toByteArray(Charsets.UTF_8) }
    }
}

/** Merapikan isian SNI/host dari pengguna dan mengenali IP literal (yang tidak boleh dikirim sebagai SNI). */
object SniUtil {
    /** Membuang skema (https://), path, dan ":port" yang sering ikut tertempel. IPv6 dibiarkan utuh. */
    fun normalize(raw: String): String {
        var v = raw.trim()
        v = v.substringAfter("://", v)
        v = v.substringBefore('/').substringBefore('?').substringBefore('#')
        if (v.startsWith("[") && v.contains("]")) return v.substring(1, v.indexOf(']')) // [::1]:443
        if (v.count { it == ':' } == 1) v = v.substringBefore(':') // host:port
        return v.trimEnd('.')
    }

    fun isIpLiteral(value: String): Boolean =
        value.contains(':') || Regex("""^\d{1,3}(\.\d{1,3}){3}$""").matches(value)
}

/** Membuat [TransportSocket] sesuai konfigurasi, atau socket biasa jika koneksi langsung. */
class TransportSocketFactory(
    private val config: TransportConfig,
    private val sshHost: String,
    private val sshPort: Int,
    private val protect: (Socket) -> Boolean,
    private val log: (String) -> Unit = {},
) : SocketFactory() {

    /** Socket dikecualikan dari VPN (VpnService.protect) supaya tidak masuk ke tunnel-nya sendiri. */
    private fun raw(): Socket = Socket().also {
        try {
            protect(it)
        } catch (_: Exception) {
            // Aplikasi ini juga dikecualikan lewat addDisallowedApplication, jadi aman jika gagal.
        }
    }

    override fun createSocket(): Socket =
        if (config.isDirect) raw() else TransportSocket(config, sshHost, sshPort, ::raw, log)

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

/**
 * Socket yang menjalankan tahap TLS dan payload di dalam [connect], lalu meneruskan semua panggilan ke
 * socket sebenarnya. Dibuat sebagai subclass [Socket] agar bisa dipasang lewat SocketFactory sshj tanpa
 * mengubah sshj.
 *
 * Keamanan: sertifikat TLS TIDAK diverifikasi, karena pada pola SNI palsu (domain "bug") sertifikat
 * memang tidak akan cocok. Ini aman untuk keutuhan data karena SSH di dalamnya tetap diverifikasi lewat
 * host key yang dipin pengguna; TLS di sini hanya berfungsi menyamarkan lalu lintas.
 */
class TransportSocket(
    private val config: TransportConfig,
    private val sshHost: String,
    private val sshPort: Int,
    private val newRawSocket: () -> Socket,
    private val log: (String) -> Unit = {},
) : Socket() {

    @Volatile
    private var inner: Socket? = null

    @Volatile
    private var stream: InputStream? = null

    @Volatile
    private var closedFlag = false
    private var soTimeoutValue = 0

    override fun connect(endpoint: SocketAddress, timeout: Int) {
        if (closedFlag) throw SocketException("Socket is closed")
        val resolved = endpoint as? InetSocketAddress ?: throw IllegalArgumentException("Unsupported address type")

        val raw = newRawSocket()
        inner = raw // disimpan lebih awal supaya close() dari thread lain bisa membatalkan connect
        try {
            val target = if (config.hasProxy) InetSocketAddress(config.proxyHost, config.proxyPort) else resolved
            raw.tcpNoDelay = true
            raw.connect(target, timeout)

            var socket: Socket = raw
            if (config.useTls) {
                val sni = SniUtil.normalize(config.sni)
                if (sni != config.sni.trim()) log("SNI dirapikan: \"${config.sni.trim()}\" -> \"$sni\"")
                val tlsHost = sni.ifBlank { SniUtil.normalize(config.proxyHost).ifBlank { SniUtil.normalize(sshHost) } }
                if (SniUtil.isIpLiteral(tlsHost)) {
                    log("Peringatan: SNI \"$tlsHost\" berupa IP, jadi SNI TIDAK dikirim. " +
                        "Server berbasis CDN (mis. CloudFront) menolak TLS tanpa SNI. Isi kolom SNI dengan nama domain.")
                } else {
                    log("TLS dengan SNI: $tlsHost")
                }
                if (target.port == 80) {
                    log("Peringatan: port 80 biasanya HTTP polos, bukan TLS. Jika server memang HTTP/WebSocket, pakai mode \"Payload HTTP\".")
                }
                raw.soTimeout = HANDSHAKE_TIMEOUT_MS
                socket = wrapTls(raw, tlsHost, target.port)
                inner = socket
            }

            var input: InputStream = socket.getInputStream()
            if (config.hasPayload) {
                socket.soTimeout = HANDSHAKE_TIMEOUT_MS
                val pushback = PushbackInputStream(input, PUSHBACK_SIZE)
                val out = socket.getOutputStream()
                sendPayload(out)
                readResponse(pushback)
                input = pushback
            }
            socket.soTimeout = soTimeoutValue
            stream = input
        } catch (t: Throwable) {
            try {
                inner?.close()
            } catch (_: Exception) {
            }
            inner = null
            throw if (t is IOException) t else IOException(t.message ?: t.javaClass.simpleName, t)
        }
    }

    override fun connect(endpoint: SocketAddress) = connect(endpoint, 0)

    // ------------------------------------------------------------ tahap TLS dan payload

    private fun wrapTls(raw: Socket, host: String, port: Int): SSLSocket {
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf(TrustAllManager), SecureRandom())
        val useName = !SniUtil.isIpLiteral(host)
        // Argumen host menjadi SNI bawaan. IP literal tidak boleh dikirim sebagai SNI.
        val ssl = context.socketFactory.createSocket(raw, if (useName) host else sshHost, port, true) as SSLSocket
        try {
            val params: SSLParameters = ssl.sslParameters
            params.serverNames = if (useName) listOf(SNIHostName(host)) else emptyList()
            ssl.sslParameters = params
        } catch (_: Exception) {
            // Platform lama tanpa SNIHostName: SNI bawaan dari argumen host tetap dipakai.
        }
        ssl.startHandshake()
        return ssl
    }

    private fun sendPayload(out: OutputStream) {
        val parts = PayloadBuilder.build(config.payload, sshHost, sshPort)
        log("Mengirim payload (${parts.size} bagian)")
        parts.forEachIndexed { index, part ->
            out.write(part)
            out.flush()
            if (index < parts.lastIndex) Thread.sleep(SPLIT_DELAY_MS)
        }
    }

    /**
     * Balasan bisa berupa header HTTP (101 Switching Protocols, 200 Connection established, dll.) atau
     * langsung banner SSH ("SSH-2.0-...") bila server tidak membalas dengan HTTP. Byte tidak pernah
     * dibaca lebih dari yang perlu, supaya awal data SSH tidak ikut terbuang.
     */
    private fun readResponse(input: PushbackInputStream) {
        val head = ByteArray(4)
        var read = 0
        try {
            while (read < head.size) {
                val n = input.read(head, read, head.size - read)
                if (n < 0) throw IOException("Server menutup koneksi setelah payload dikirim")
                read += n
            }
        } catch (e: SocketTimeoutException) {
            throw IOException("Tidak ada balasan dari server/proxy setelah payload (waktu habis)", e)
        }
        if (String(head, Charsets.ISO_8859_1) != "HTTP") {
            input.unread(head) // bukan HTTP: anggap data SSH
            return
        }

        val buffer = ByteArrayOutputStream().apply { write(head) }
        val data = StringBuilder("HTTP")
        try {
            while (true) {
                val b = input.read()
                if (b < 0) throw IOException("Server menutup koneksi sebelum header selesai")
                buffer.write(b)
                data.append(b.toChar())
                if (data.endsWith("\r\n\r\n") || data.endsWith("\n\n")) break
                if (buffer.size() > MAX_RESPONSE_HEADER) throw IOException("Header balasan terlalu besar")
            }
        } catch (e: SocketTimeoutException) {
            throw IOException("Header balasan tidak lengkap (waktu habis)", e)
        }
        val statusLine = data.lineSequence().first().trim()
        val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull()
        log("Balasan: $statusLine")
        if (code == null || code !in 100..299) {
            throw IOException("Payload ditolak: $statusLine")
        }
    }

    // ------------------------------------------------------------ delegasi ke socket sebenarnya

    override fun getInputStream(): InputStream = stream ?: throw SocketException("Socket is not connected")

    override fun getOutputStream(): OutputStream =
        inner?.getOutputStream() ?: throw SocketException("Socket is not connected")

    override fun close() {
        closedFlag = true
        try {
            inner?.close()
        } catch (_: Exception) {
        }
        try {
            super.close()
        } catch (_: Exception) {
        }
    }

    override fun isClosed(): Boolean = closedFlag || inner?.isClosed == true
    override fun isConnected(): Boolean = stream != null && inner?.isConnected == true
    override fun isBound(): Boolean = inner?.isBound == true

    override fun setSoTimeout(timeout: Int) {
        soTimeoutValue = timeout
        inner?.soTimeout = timeout
    }

    override fun getSoTimeout(): Int = soTimeoutValue
    override fun setTcpNoDelay(on: Boolean) {
        inner?.tcpNoDelay = on
    }

    override fun getTcpNoDelay(): Boolean = inner?.tcpNoDelay ?: false
    override fun setKeepAlive(on: Boolean) {
        inner?.keepAlive = on
    }

    override fun getKeepAlive(): Boolean = inner?.keepAlive ?: false
    override fun shutdownInput() {
        inner?.shutdownInput()
    }

    override fun shutdownOutput() {
        inner?.shutdownOutput()
    }

    override fun isInputShutdown(): Boolean = inner?.isInputShutdown == true
    override fun isOutputShutdown(): Boolean = inner?.isOutputShutdown == true
    override fun getInetAddress(): InetAddress? = inner?.inetAddress
    override fun getPort(): Int = inner?.port ?: 0
    override fun getLocalPort(): Int = inner?.localPort ?: -1
    override fun getRemoteSocketAddress(): SocketAddress? = inner?.remoteSocketAddress
    override fun getLocalSocketAddress(): SocketAddress? = inner?.localSocketAddress

    private object TrustAllManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private companion object {
        const val HANDSHAKE_TIMEOUT_MS = 15_000
        const val SPLIT_DELAY_MS = 250L
        const val PUSHBACK_SIZE = 8
        const val MAX_RESPONSE_HEADER = 16 * 1024
    }
}
