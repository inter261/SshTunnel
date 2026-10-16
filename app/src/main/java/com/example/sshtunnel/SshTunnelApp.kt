package com.example.sshtunnel

import android.app.Application
import com.example.sshtunnel.data.ProfileStore
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class SshTunnelApp : Application() {

    /** Satu instance dipakai bersama UI dan service. */
    val store: ProfileStore by lazy { ProfileStore(this) }

    override fun onCreate() {
        super.onCreate()
        // Android membawa BouncyCastle versi terpotong dengan nama "BC". sshj butuh yang lengkap
        // (Ed25519, Curve25519, ChaCha20-Poly1305, dll.), jadi gantikan sebelum sshj dipakai.
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }
}
