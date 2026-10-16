package com.example.sshtunnel.core

import java.io.IOException

sealed interface TunnelError {
    data class Message(val text: String) : TunnelError

    /** Host key belum pernah dipercaya: pengguna harus memverifikasi fingerprint dulu. */
    data class HostKeyUnknown(val keyType: String, val fingerprint: String) : TunnelError

    /** Host key berbeda dari yang dipercaya: bisa jadi server diganti atau ada serangan MITM. */
    data class HostKeyChanged(val expected: String, val actual: String) : TunnelError
}

sealed interface TunnelState {
    data object Disconnected : TunnelState
    data class Connecting(val step: String) : TunnelState
    data class Connected(val profileName: String, val sinceMillis: Long) : TunnelState
    data class Reconnecting(val attempt: Int, val reason: String) : TunnelState
    data class Failed(val profileId: String, val error: TunnelError) : TunnelState
}

/** Statistik lalu lintas sejak tunnel tersambung. Rate dalam byte/detik. */
data class Traffic(
    val downloadBytes: Long = 0,
    val uploadBytes: Long = 0,
    val downloadRate: Long = 0,
    val uploadRate: Long = 0,
)

/** Dilempar saat verifikasi host key gagal; membawa jenis kesalahan yang tepat untuk UI. */
class HostKeyException(val error: TunnelError) : IOException(
    when (error) {
        is TunnelError.HostKeyUnknown -> "Host key belum dipercaya"
        is TunnelError.HostKeyChanged -> "Host key berubah"
        is TunnelError.Message -> error.text
    },
)

/** Kesalahan yang tidak ada gunanya dicoba ulang otomatis (mis. password salah). */
class FatalTunnelException(message: String, cause: Throwable? = null) : IOException(message, cause)
