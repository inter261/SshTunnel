package com.example.sshtunnel

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import com.example.sshtunnel.ui.MainScreen
import com.example.sshtunnel.vpn.TunnelVpnService

class MainActivity : ComponentActivity() {

    private val store get() = (application as SshTunnelApp).store

    /** Profil yang menunggu izin VPN / notifikasi sebelum benar-benar disambungkan. */
    private var pendingProfileId: String? = null

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                pendingProfileId?.let { launchService(it) }
            }
            pendingProfileId = null
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Ditolak pun tidak apa-apa: tunnel tetap jalan, hanya notifikasinya tidak terlihat.
            pendingProfileId?.let { requestVpnPermission(it) }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AppTheme {
                MainScreen(
                    store = store,
                    onConnect = ::connect,
                    onDisconnect = {
                        startService(TunnelVpnService.stopIntent(this))
                    },
                )
            }
        }
    }

    private fun connect(profileId: String) {
        pendingProfileId = profileId
        val needsNotificationPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        if (needsNotificationPermission) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnPermission(profileId)
        }
    }

    private fun requestVpnPermission(profileId: String) {
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            launchService(profileId)
            pendingProfileId = null
        } else {
            vpnPermission.launch(prepare)
        }
    }

    private fun launchService(profileId: String) {
        ContextCompat.startForegroundService(this, TunnelVpnService.startIntent(this, profileId))
    }
}

@Composable
private fun AppTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = if (dark) darkColorScheme() else lightColorScheme(),
        content = content,
    )
}
