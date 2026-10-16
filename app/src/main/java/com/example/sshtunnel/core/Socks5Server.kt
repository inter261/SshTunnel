package com.example.sshtunnel.core

import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Server SOCKS5 lokal (hanya di 127.0.0.1) yang meneruskan semua koneksi lewat SSH (direct-tcpip).
 * Padanan `ssh -D` — dibuat sendiri supaya koneksi SSH bisa diganti saat reconnect
 * tanpa menutup port lokal yang dipakai tun2socks.
 *
 * - Auth wajib username/password acak per sesi, supaya aplikasi lain di perangkat
 *   tidak bisa ikut menumpang tunnel lewat port lokal ini.
 * - CONNECT: diteruskan sebagai kanal direct-tcpip.
 * - UDP ASSOCIATE: hanya DNS (port 53). Query DNS dikirim ke [dnsServer] lewat TCP di dalam tunnel
 *   (DNS-over-TCP, RFC 7766), jadi tidak ada DNS leak. Datagram UDP lain dibuang
 *   (SSH memang tidak punya UDP; aplikasi seperti QUIC akan fallback ke TCP).
 */
class Socks5Server(
    username: String,
    password: String,
    private val connector: () -> SshConnector?,
    private val dnsServer: () -> String,
    private val log: (String) -> Unit = {},
) : Closeable {

    private val userBytes = username.toByteArray(Charsets.UTF_8)
    private val passBytes = password.toByteArray(Charsets.UTF_8)
    private val loopback: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val server = ServerSocket()
    private val pool = Executors.newCachedThreadPool { r -> Thread(r, "socks5").apply { isDaemon = true } }
    private val open = ConcurrentHashMap.newKeySet<Closeable>()

    @Volatile
    private var closed = false

    /** Port lokal yang dipilih sistem (valid setelah [start]). */
    val port: Int get() = server.localPort

    fun start() {
        server.reuseAddress = true
        server.bind(InetSocketAddress(loopback, 0), 256)
        pool.execute { acceptLoop() }
    }

    override fun close() {
        if (closed) return
        closed = true
        closeQuietly(server)
        open.forEach { closeQuietly(it) }
        open.clear()
        pool.shutdownNow()
    }

    private fun acceptLoop() {
        while (!closed) {
            val client = try {
                server.accept()
            } catch (e: IOException) {
                if (closed) return
                log("SOCKS accept error: ${e.message}")
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    return
                }
                continue
            }
            try {
                pool.execute { handle(client) }
            } catch (_: Exception) { // pool sudah ditutup
                closeQuietly(client)
                return
            }
        }
    }

    // ---------------------------------------------------------------- handshake

    private fun handle(client: Socket) {
        open.add(client)
        try {
            client.tcpNoDelay = true
            client.soTimeout = HANDSHAKE_TIMEOUT_MS
            // Tanpa buffering: byte setelah handshake harus tetap utuh untuk fase pipe.
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()

            // 1) pemilihan metode
            if (input.readUnsignedByte() != 5) return
            val methods = ByteArray(input.readUnsignedByte())
            input.readFully(methods)
            if (!methods.contains(METHOD_USERPASS)) {
                output.write(byteArrayOf(5, METHOD_NONE_ACCEPTABLE))
                output.flush()
                return
            }
            output.write(byteArrayOf(5, METHOD_USERPASS))
            output.flush()

            // 2) username/password (RFC 1929)
            if (input.readUnsignedByte() != 1) return
            val user = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
            val pass = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
            val ok = MessageDigest.isEqual(user, userBytes) and MessageDigest.isEqual(pass, passBytes)
            output.write(byteArrayOf(1, if (ok) 0 else 1))
            output.flush()
            if (!ok) return

            // 3) permintaan
            if (input.readUnsignedByte() != 5) return
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()
            val host = readAddress(input, atyp)
            if (host == null) {
                reply(output, REP_ATYP_UNSUPPORTED)
                return
            }
            val port = input.readUnsignedShort()

            when (cmd) {
                CMD_CONNECT -> handleConnect(client, output, host, port)
                CMD_UDP_ASSOCIATE -> handleUdpAssociate(client, input, output)
                else -> reply(output, REP_CMD_UNSUPPORTED)
            }
        } catch (_: IOException) {
            // klien menutup koneksi / timeout handshake
        } catch (e: Exception) {
            log("SOCKS error: $e")
        } finally {
            open.remove(client)
            closeQuietly(client)
        }
    }

    private fun readAddress(input: DataInputStream, atyp: Int): String? = when (atyp) {
        ATYP_IPV4 -> InetAddress.getByAddress(ByteArray(4).also { input.readFully(it) }).hostAddress
        ATYP_IPV6 -> InetAddress.getByAddress(ByteArray(16).also { input.readFully(it) }).hostAddress
        ATYP_DOMAIN -> String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) }, Charsets.UTF_8)
        else -> null
    }

    private fun reply(
        out: OutputStream,
        rep: Int,
        bindAddr: ByteArray = byteArrayOf(0, 0, 0, 0),
        bindPort: Int = 0,
    ) {
        out.write(byteArrayOf(5, rep.toByte(), 0, ATYP_IPV4.toByte()) + bindAddr +
            byteArrayOf((bindPort shr 8).toByte(), bindPort.toByte()))
        out.flush()
    }

    // ---------------------------------------------------------------- CONNECT

    private fun handleConnect(client: Socket, output: OutputStream, host: String, port: Int) {
        val ssh = connector()
        if (ssh == null) { // sedang reconnect: tolak cepat, jangan bocor ke jaringan langsung
            reply(output, REP_GENERAL_FAILURE)
            return
        }
        val channel = try {
            ssh.openDirect(host, port)
        } catch (e: Exception) {
            log("CONNECT $host:$port gagal: ${e.message}")
            reply(output, replyCodeFor(e))
            return
        }
        open.add(channel)
        try {
            reply(output, REP_SUCCEEDED)
            client.soTimeout = 0
            pipe(client, channel)
        } finally {
            open.remove(channel)
            closeQuietly(channel)
        }
    }

    private fun pipe(client: Socket, channel: DuplexChannel) {
        // klien -> SSH (thread lain)
        val upstream = pool.submit(Runnable {
            try {
                copy(client.getInputStream(), channel.output)
                closeQuietly(channel.output) // half-close: kirim EOF ke sisi server
            } catch (_: IOException) {
                closeQuietly(channel)
                closeQuietly(client)
            }
        })
        // SSH -> klien (thread ini)
        try {
            copy(channel.input, client.getOutputStream())
            try {
                client.shutdownOutput()
            } catch (_: IOException) {
            }
        } catch (_: IOException) {
            closeQuietly(client)
        }
        // tunggu arah sebaliknya selesai (bounded supaya tidak menggantung)
        try {
            upstream.get(HALF_CLOSE_WAIT_SECONDS, TimeUnit.SECONDS)
        } catch (_: Exception) {
        }
    }

    private fun copy(input: InputStream, output: OutputStream) {
        val buf = ByteArray(COPY_BUFFER)
        while (true) {
            val n = input.read(buf)
            if (n < 0) return
            output.write(buf, 0, n)
            output.flush()
        }
    }

    private fun replyCodeFor(e: Throwable): Int {
        val text = generateSequence(e) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" ")
            .lowercase()
        return when {
            "refused" in text -> REP_CONNECTION_REFUSED
            "timed out" in text || "timeout" in text -> REP_TTL_EXPIRED
            "unreachable" in text -> REP_NETWORK_UNREACHABLE
            else -> REP_HOST_UNREACHABLE
        }
    }

    // ---------------------------------------------------------------- UDP (DNS saja)

    private fun handleUdpAssociate(client: Socket, input: InputStream, output: OutputStream) {
        val udp = DatagramSocket(InetSocketAddress(loopback, 0))
        open.add(udp)
        try {
            reply(output, REP_SUCCEEDED, loopback.address, udp.localPort)
            client.soTimeout = 0
            pool.execute { udpLoop(udp) }
            // Asosiasi UDP hidup selama koneksi TCP kontrol ini terbuka (RFC 1928 bagian 6).
            try {
                while (input.read() >= 0) { /* abaikan */ }
            } catch (_: IOException) {
            }
        } finally {
            open.remove(udp)
            closeQuietly(udp)
        }
    }

    private fun udpLoop(udp: DatagramSocket) {
        val buf = ByteArray(65535)
        val pkt = DatagramPacket(buf, buf.size)
        while (!udp.isClosed) {
            try {
                pkt.length = buf.size
                udp.receive(pkt)
            } catch (_: IOException) {
                return
            }
            val len = pkt.length
            // RSV(2) FRAG(1) ATYP(1) ADDR... PORT(2) DATA
            if (len < 10 || buf[2].toInt() != 0) continue // fragmentasi tidak didukung
            val addrLen = when (buf[3].toInt() and 0xff) {
                ATYP_IPV4 -> 4
                ATYP_IPV6 -> 16
                ATYP_DOMAIN -> 1 + (buf[4].toInt() and 0xff)
                else -> continue
            }
            val headerEnd = 4 + addrLen + 2
            if (len < headerEnd) continue
            val dstPort = ((buf[headerEnd - 2].toInt() and 0xff) shl 8) or (buf[headerEnd - 1].toInt() and 0xff)
            if (dstPort != 53) continue // hanya DNS yang didukung
            val header = buf.copyOfRange(0, headerEnd) // dipakai ulang sebagai header balasan
            val query = buf.copyOfRange(headerEnd, len)
            val replyTo = InetSocketAddress(pkt.address, pkt.port)
            try {
                pool.execute { resolveDns(udp, header, query, replyTo) }
            } catch (_: Exception) {
                return
            }
        }
    }

    /** Satu query DNS = satu kanal ke resolver di dalam tunnel (format TCP: panjang 2 byte + pesan). */
    private fun resolveDns(udp: DatagramSocket, header: ByteArray, query: ByteArray, to: SocketAddress) {
        if (query.size < 12) return
        val ssh = connector() ?: return
        val channel = try {
            ssh.openDirect(dnsServer(), 53)
        } catch (e: Exception) {
            log("DNS: gagal membuka kanal: ${e.message}")
            return
        }
        val watchdog = Timers.schedule(DNS_TIMEOUT_MS) { closeQuietly(channel) }
        try {
            channel.output.write(byteArrayOf((query.size shr 8).toByte(), query.size.toByte()))
            channel.output.write(query)
            channel.output.flush()
            val din = DataInputStream(channel.input)
            val response = ByteArray(din.readUnsignedShort()).also { din.readFully(it) }
            if (!udp.isClosed) {
                val packet = header + response
                udp.send(DatagramPacket(packet, packet.size, to))
            }
        } catch (_: IOException) {
            log("DNS: timeout / kanal terputus")
        } finally {
            watchdog.cancel(false)
            closeQuietly(channel)
        }
    }

    // ---------------------------------------------------------------- util

    private fun closeQuietly(c: Closeable?) {
        try {
            c?.close()
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val HANDSHAKE_TIMEOUT_MS = 10_000
        const val HALF_CLOSE_WAIT_SECONDS = 20L
        const val DNS_TIMEOUT_MS = 5_000L
        const val COPY_BUFFER = 16 * 1024

        const val METHOD_USERPASS: Byte = 2
        const val METHOD_NONE_ACCEPTABLE: Byte = -1 // 0xFF

        const val CMD_CONNECT = 1
        const val CMD_UDP_ASSOCIATE = 3

        const val ATYP_IPV4 = 1
        const val ATYP_DOMAIN = 3
        const val ATYP_IPV6 = 4

        const val REP_SUCCEEDED = 0
        const val REP_GENERAL_FAILURE = 1
        const val REP_NETWORK_UNREACHABLE = 3
        const val REP_HOST_UNREACHABLE = 4
        const val REP_CONNECTION_REFUSED = 5
        const val REP_TTL_EXPIRED = 6
        const val REP_CMD_UNSUPPORTED = 7
        const val REP_ATYP_UNSUPPORTED = 8
    }
}
