package com.example.sshtunnel.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import com.example.sshtunnel.MainActivity
import com.example.sshtunnel.R
import com.example.sshtunnel.SshTunnelApp
import com.example.sshtunnel.core.TunnelError
import com.example.sshtunnel.core.TunnelManager
import com.example.sshtunnel.core.TunnelState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Service VPN + foreground service. Logika tunnel ada di [TunnelSession]; kelas ini hanya mengurus
 * siklus hidup service, notifikasi, dan menyediakan akses ke API VpnService (Builder, protect).
 */
class TunnelVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var session: TunnelSession? = null
    private var sessionJob: Job? = null
    private var notificationJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> start(intent.getStringExtra(EXTRA_PROFILE_ID))
            ACTION_STOP -> stopTunnel()
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    /** Dipanggil sistem saat izin VPN dicabut atau aplikasi VPN lain mengambil alih. */
    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        session?.abort()
        scope.cancel()
        super.onDestroy()
    }

    /** Dipakai [TunnelSession]; Builder adalah inner class sehingga hanya bisa dibuat dari dalam service. */
    fun newBuilder(): Builder = Builder()

    // ---------------------------------------------------------------- siklus hidup

    private fun start(profileId: String?) {
        // Wajib segera dipanggil setelah startForegroundService().
        startForegroundCompat(buildNotification("Menghubungkan ..."))

        if (sessionJob?.isCompleted == false) return // sudah berjalan

        val profile = profileId?.let { (application as SshTunnelApp).store.get(it) }
        if (profile == null) {
            TunnelManager.setState(
                TunnelState.Failed(profileId.orEmpty(), TunnelError.Message("Profil tidak ditemukan")),
            )
            shutdown()
            return
        }
        profile.validate()?.let { problem ->
            TunnelManager.setState(TunnelState.Failed(profile.id, TunnelError.Message(problem)))
            shutdown()
            return
        }

        TunnelManager.clearLog()
        val newSession = TunnelSession(this, profile)
        session = newSession
        sessionJob = scope.launch {
            try {
                newSession.run()
            } finally {
                withContext(NonCancellable) { shutdown() }
            }
        }
        notificationJob?.cancel()
        notificationJob = scope.launch(Dispatchers.Main) {
            TunnelManager.state.collect { updateNotification(it) }
        }
    }

    private fun stopTunnel() {
        session?.abort()
        val job = sessionJob
        if (job == null || job.isCompleted) {
            shutdown()
        } else {
            job.cancel() // run() membersihkan sumber daya, lalu memanggil shutdown()
        }
    }

    private fun shutdown() {
        notificationJob?.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ---------------------------------------------------------------- notifikasi

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(CHANNEL_ID, "Status tunnel", NotificationManager.IMPORTANCE_LOW)
        channel.setShowBadge(false)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(text: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_tunnel)
        .setContentTitle("SSH Tunnel")
        .setContentText(text)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setContentIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
        .addAction(
            0,
            "Putus",
            PendingIntent.getService(
                this,
                1,
                stopIntent(this),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
        .build()

    private fun updateNotification(state: TunnelState) {
        val text = when (state) {
            is TunnelState.Connecting -> "${state.step} ..."
            is TunnelState.Connected -> "Tersambung: ${state.profileName}"
            is TunnelState.Reconnecting -> "Menyambung ulang (${state.reason})"
            else -> return
        }
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun startForegroundCompat(notification: android.app.Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        private const val ACTION_START = "com.example.sshtunnel.action.START"
        private const val ACTION_STOP = "com.example.sshtunnel.action.STOP"
        private const val EXTRA_PROFILE_ID = "profile_id"
        private const val CHANNEL_ID = "tunnel_status"
        private const val NOTIFICATION_ID = 1

        fun startIntent(context: Context, profileId: String): Intent =
            Intent(context, TunnelVpnService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PROFILE_ID, profileId)

        fun stopIntent(context: Context): Intent =
            Intent(context, TunnelVpnService::class.java).setAction(ACTION_STOP)
    }
}
