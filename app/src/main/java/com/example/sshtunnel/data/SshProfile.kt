package com.example.sshtunnel.data

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
) {
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
        )
    }
}
