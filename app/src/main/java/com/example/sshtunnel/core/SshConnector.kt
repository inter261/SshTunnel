package com.example.sshtunnel.core

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

/**
 * Satu kanal dua arah ke tujuan di sisi server SSH (direct-tcpip).
 * Sengaja tidak bergantung pada sshj/Android supaya [Socks5Server] bisa diuji di JVM biasa.
 */
interface DuplexChannel : Closeable {
    val input: InputStream
    val output: OutputStream
}

/** Pembuat kanal ke tujuan lewat server SSH. */
interface SshConnector {
    /** Memblokir sampai kanal terbuka. Melempar IOException jika ditolak/gagal. */
    fun openDirect(host: String, port: Int): DuplexChannel
}
