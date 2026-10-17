package com.example.sshtunnel.data

import com.example.sshtunnel.core.TransportConfig
import org.json.JSONObject
import java.util.UUID

enum class AuthType { PASSWORD, PRIVATE_KEY }

data class SshProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    val host: String = "",
    val port: Int = 22,
    val username: String = "",
    val authType: AuthType = AuthType.PASSWORD,
    val password: String = "",
    /** Isi file private key (OpenSSH / PEM / PuTTY .ppk), bukan path-nya. */
    val privateKey: String = "",
    val keyPassphrase: String = "",
    val compression: Boolean = false,
    val keepAliveSeconds: Int = 20,
    /** Resolver DNS yang dijangkau lewat tunnel (DNS-over-TCP di dalam SSH). */
    val dnsServer: String = "8.8.8.8",
    /** Fingerprint host key yang sudah dipercaya pengguna, format "SHA256:...". Kosong = belum dipercaya. */
    val trustedHostKey: String = "",
    /** Bungkus koneksi dengan TLS (mirip stunnel), dengan SNI di bawah. */
    val useTls: Boolean = false,
    /** Nama yang dikirim di SNI. Kosong = pakai host. */
    val sni: String = "",
    /** Template payload HTTP; kosong = tanpa payload. Lihat PayloadBuilder untuk placeholder. */
    val payload: String = "",
    /** Jika diisi, koneksi dibuka ke proxy ini dulu (payload biasanya CONNECT [host_port]). */
    val proxyHost: String = "",
    val proxyPort: Int = 8080,
) {
    val transport: TransportConfig
        get() = TransportConfig(
            useTls = useTls,
            sni = sni.trim(),
            payload = payload,
            proxyHost = proxyHost.trim(),
            proxyPort = proxyPort,
        )

    val displayName: String
        get() = name.ifBlank { "${username.ifBlank { "?" }}@${host.ifBlank { "?" }}" }

    /** Pesan kesalahan untuk ditampilkan di form, atau null jika profil valid. */
    fun validate(): String? = when {
        host.isBlank() -> "Host wajib diisi"
        host.any { it.isWhitespace() } -> "Host tidak boleh mengandung spasi"
        port !in 1..65535 -> "Port harus 1–65535"
        username.isBlank() -> "Username wajib diisi"
        authType == AuthType.PASSWORD && password.isEmpty() -> "Password wajib diisi"
        authType == AuthType.PRIVATE_KEY && privateKey.isBlank() -> "Private key wajib diisi"
        keepAliveSeconds !in 5..300 -> "Keepalive harus 5–300 detik"
        dnsServer.isBlank() || dnsServer.any { it.isWhitespace() } -> "DNS server tidak valid"
        sni.any { it.isWhitespace() } -> "SNI tidak boleh mengandung spasi"
        proxyHost.isNotBlank() && payload.isBlank() -> "Proxy butuh payload (mis. CONNECT [host_port] HTTP/1.1)"
        proxyHost.isNotBlank() && proxyPort !in 1..65535 -> "Port proxy harus 1–65535"
        proxyHost.any { it.isWhitespace() } -> "Host proxy tidak boleh mengandung spasi"
        else -> null
    }

    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("name", name)
        .put("host", host)
        .put("port", port)
        .put("username", username)
        .put("authType", authType.name)
        .put("password", password)
        .put("privateKey", privateKey)
        .put("keyPassphrase", keyPassphrase)
        .put("compression", compression)
        .put("keepAliveSeconds", keepAliveSeconds)
        .put("dnsServer", dnsServer)
        .put("trustedHostKey", trustedHostKey)
        .put("useTls", useTls)
        .put("sni", sni)
        .put("payload", payload)
        .put("proxyHost", proxyHost)
        .put("proxyPort", proxyPort)

    companion object {
        fun fromJson(o: JSONObject): SshProfile = SshProfile(
            id = o.optString("id").ifBlank { UUID.randomUUID().toString() },
            name = o.optString("name"),
            host = o.optString("host"),
            port = o.optInt("port", 22),
            username = o.optString("username"),
            authType = runCatching { AuthType.valueOf(o.optString("authType")) }.getOrDefault(AuthType.PASSWORD),
            password = o.optString("password"),
            privateKey = o.optString("privateKey"),
            keyPassphrase = o.optString("keyPassphrase"),
            compression = o.optBoolean("compression", false),
            keepAliveSeconds = o.optInt("keepAliveSeconds", 20),
            dnsServer = o.optString("dnsServer").ifBlank { "8.8.8.8" },
            trustedHostKey = o.optString("trustedHostKey"),
            useTls = o.optBoolean("useTls", false),
            sni = o.optString("sni"),
            payload = o.optString("payload"),
            proxyHost = o.optString("proxyHost"),
            proxyPort = o.optInt("proxyPort", 8080),
        )
    }
}
