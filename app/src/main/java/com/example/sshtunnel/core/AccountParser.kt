package com.example.sshtunnel.core

data class ParsedAccount(
    val host: String,
    val port: Int,
    val username: String,
    val password: String,
)

/**
 * Membaca akun satu baris seperti yang dibagikan untuk aplikasi tunnel SSH:
 *
 *   host:port@username:password            (format utama)
 *   host@username:password                 (port 22)
 *   [2001:db8::1]:2222@username:password   (IPv6 dalam kurung)
 *   ssh://username:password@host:port      (gaya URL)
 *
 * Password boleh mengandung ':' dan '@' (semua setelah ':' pertama di bagian user dianggap password).
 * Yang dibaca hanya baris tidak kosong pertama. Mengembalikan null jika formatnya tidak dikenali.
 */
object AccountParser {
    fun parse(input: String): ParsedAccount? {
        var text = input.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() } ?: return null
        text = text.trim('`', '"', '\'')

        val urlStyle = text.startsWith("ssh://", ignoreCase = true)
        if (urlStyle) text = text.substring("ssh://".length)

        val hostPart: String
        val userPart: String
        if (urlStyle) {
            // user:pass@host:port — password boleh berisi '@', jadi pisah di '@' TERAKHIR
            val at = text.lastIndexOf('@')
            if (at < 0) return null
            userPart = text.substring(0, at)
            hostPart = text.substring(at + 1)
        } else {
            // host:port@user:pass — host tidak mungkin berisi '@', jadi pisah di '@' PERTAMA
            val at = text.indexOf('@')
            if (at < 0) return null
            hostPart = text.substring(0, at)
            userPart = text.substring(at + 1)
        }

        val colon = userPart.indexOf(':')
        if (colon <= 0) return null // username kosong atau tidak ada password
        val username = userPart.substring(0, colon)
        val password = userPart.substring(colon + 1)
        if (password.isEmpty()) return null

        val (host, port) = parseHostPort(hostPart) ?: return null
        return ParsedAccount(host, port, username, password)
    }

    private fun parseHostPort(value: String): Pair<String, Int>? {
        val v = value.trim()
        if (v.isEmpty()) return null

        if (v.startsWith("[")) {
            val end = v.indexOf(']')
            if (end < 0) return null
            val host = v.substring(1, end)
            val rest = v.substring(end + 1)
            if (host.isEmpty()) return null
            return when {
                rest.isEmpty() -> host to DEFAULT_PORT
                rest.startsWith(":") -> parsePort(rest.substring(1))?.let { host to it }
                else -> null
            }
        }

        return when (v.count { it == ':' }) {
            0 -> if (v.any { it.isWhitespace() }) null else v to DEFAULT_PORT
            1 -> {
                val host = v.substringBefore(':')
                val port = parsePort(v.substringAfter(':')) ?: return null
                if (host.isEmpty() || host.any { it.isWhitespace() }) null else host to port
            }
            else -> null // IPv6 tanpa kurung: ambigu antara alamat dan port
        }
    }

    private fun parsePort(value: String): Int? =
        value.takeIf { it.isNotEmpty() && it.all(Char::isDigit) && it.length <= 5 }
            ?.toInt()?.takeIf { it in 1..65535 }

    private const val DEFAULT_PORT = 22
}
