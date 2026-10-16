package com.example.sshtunnel.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.sshtunnel.core.TunnelError
import com.example.sshtunnel.core.TunnelManager
import com.example.sshtunnel.core.TunnelState
import com.example.sshtunnel.data.ProfileStore
import com.example.sshtunnel.data.SshProfile
import kotlinx.coroutines.delay
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    store: ProfileStore,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    val profiles = remember { mutableStateListOf<SshProfile>().apply { addAll(store.load()) } }
    var selectedId by remember { mutableStateOf(store.selectedId) }
    var editing by remember { mutableStateOf<SshProfile?>(null) }
    var showLog by remember { mutableStateOf(false) }

    val state by TunnelManager.state.collectAsStateWithLifecycle()
    val traffic by TunnelManager.traffic.collectAsStateWithLifecycle()
    val log by TunnelManager.log.collectAsStateWithLifecycle()

    fun reload() {
        profiles.clear()
        profiles.addAll(store.load())
        if (profiles.none { it.id == selectedId }) selectedId = profiles.firstOrNull()?.id
        store.selectedId = selectedId
    }

    if (selectedId == null && profiles.isNotEmpty()) selectedId = profiles.first().id
    val selected = profiles.firstOrNull { it.id == selectedId }
    val busy = TunnelManager.isActive

    // Layar editor menggantikan layar utama selama ada profil yang diedit.
    editing?.let { current ->
        ProfileEditorScreen(
            initial = current,
            isNew = profiles.none { it.id == current.id },
            onSave = {
                store.upsert(it)
                selectedId = it.id
                reload()
                editing = null
            },
            onDelete = {
                store.delete(current.id)
                reload()
                editing = null
            },
            onCancel = { editing = null },
        )
        return
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("SSH Tunnel") }) },
        floatingActionButton = {
            if (!busy) {
                ExtendedFloatingActionButton(
                    onClick = { editing = SshProfile() },
                    text = { Text("Profil baru") },
                    icon = { Text("+", fontSize = 20.sp) },
                )
            }
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusCard(
                state = state,
                traffic = traffic,
                canConnect = selected != null,
                onConnect = { selected?.let { onConnect(it.id) } },
                onDisconnect = onDisconnect,
                onShowLog = { showLog = true },
            )

            if (profiles.isEmpty()) {
                Text(
                    "Belum ada profil. Ketuk “Profil baru” untuk menambahkan server SSH.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 24.dp),
                )
            } else {
                Text("Profil", style = MaterialTheme.typography.titleSmall)
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(bottom = 96.dp),
                ) {
                    items(profiles, key = { it.id }) { profile ->
                        ProfileRow(
                            profile = profile,
                            selected = profile.id == selectedId,
                            enabled = !busy,
                            onSelect = {
                                selectedId = profile.id
                                store.selectedId = profile.id
                            },
                            onEdit = { editing = profile },
                        )
                    }
                }
            }
        }
    }

    // Dialog verifikasi host key (muncul saat server belum dipercaya atau kuncinya berubah).
    val failed = state as? TunnelState.Failed
    if (failed != null) {
        when (val error = failed.error) {
            is TunnelError.HostKeyUnknown -> HostKeyDialog(
                title = "Percayai server ini?",
                body = "Ini pertama kali terhubung ke server ini. Cocokkan fingerprint di bawah dengan " +
                    "yang ada di server (jalankan `ssh-keygen -lf /etc/ssh/ssh_host_${keyFileSuffix(error.keyType)}_key.pub`) " +
                    "sebelum melanjutkan.",
                detail = "${error.keyType}\n${error.fingerprint}",
                confirmLabel = "Percayai & sambung",
                onConfirm = {
                    store.trustHostKey(failed.profileId, error.fingerprint)
                    reload()
                    TunnelManager.setState(TunnelState.Disconnected)
                    onConnect(failed.profileId)
                },
                onDismiss = { TunnelManager.setState(TunnelState.Disconnected) },
            )

            is TunnelError.HostKeyChanged -> HostKeyDialog(
                title = "Host key BERUBAH",
                body = "Fingerprint server berbeda dari yang pernah dipercaya. Bisa jadi server dipasang ulang, " +
                    "tetapi bisa juga ada pihak lain yang menyadap koneksi (MITM). Jangan lanjut kecuali Anda " +
                    "yakin server memang diganti.",
                detail = "Dipercaya:\n${error.expected}\n\nSekarang:\n${error.actual}",
                confirmLabel = "Percayai kunci baru",
                onConfirm = {
                    store.trustHostKey(failed.profileId, error.actual)
                    reload()
                    TunnelManager.setState(TunnelState.Disconnected)
                    onConnect(failed.profileId)
                },
                onDismiss = { TunnelManager.setState(TunnelState.Disconnected) },
            )

            is TunnelError.Message -> AlertDialog(
                onDismissRequest = { TunnelManager.setState(TunnelState.Disconnected) },
                title = { Text("Gagal tersambung") },
                text = { Text(error.text) },
                confirmButton = {
                    TextButton(onClick = { TunnelManager.setState(TunnelState.Disconnected) }) { Text("Tutup") }
                },
                dismissButton = { TextButton(onClick = { showLog = true }) { Text("Lihat log") } },
            )
        }
    }

    if (showLog) {
        AlertDialog(
            onDismissRequest = { showLog = false },
            title = { Text("Log") },
            text = {
                SelectionContainer {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Text(
                            if (log.isEmpty()) "(kosong)" else log.joinToString("\n"),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        )
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showLog = false }) { Text("Tutup") } },
            dismissButton = { TextButton(onClick = { TunnelManager.clearLog() }) { Text("Bersihkan") } },
        )
    }
}

@Composable
private fun StatusCard(
    state: TunnelState,
    traffic: com.example.sshtunnel.core.Traffic,
    canConnect: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onShowLog: () -> Unit,
) {
    val connected = state as? TunnelState.Connected
    // Pewaktu durasi: memicu recomposition tiap detik hanya saat tersambung.
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(connected) {
        while (connected != null) {
            now = System.currentTimeMillis()
            delay(1_000)
        }
    }

    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (state) {
                is TunnelState.Connected -> MaterialTheme.colorScheme.primaryContainer
                is TunnelState.Failed -> MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                when (state) {
                    is TunnelState.Disconnected -> "Terputus"
                    is TunnelState.Connecting -> state.step
                    is TunnelState.Connected -> "Tersambung"
                    is TunnelState.Reconnecting ->
                        "Menyambung ulang" + if (state.attempt > 0) " (percobaan ${state.attempt})" else ""
                    is TunnelState.Failed -> "Gagal"
                },
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
            when (state) {
                is TunnelState.Connected -> {
                    Text(state.profileName, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Durasi ${formatDuration(now - state.sinceMillis)}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "↓ ${formatBytes(traffic.downloadBytes)}  (${formatBytes(traffic.downloadRate)}/s)    " +
                            "↑ ${formatBytes(traffic.uploadBytes)}  (${formatBytes(traffic.uploadRate)}/s)",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }

                is TunnelState.Reconnecting -> Text(state.reason, style = MaterialTheme.typography.bodySmall)
                else -> Unit
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                if (TunnelManager.isActive) {
                    Button(onClick = onDisconnect) { Text("Putus") }
                } else {
                    Button(onClick = onConnect, enabled = canConnect) { Text("Sambung") }
                }
                OutlinedButton(onClick = onShowLog) { Text("Log") }
            }
        }
    }
}

@Composable
private fun ProfileRow(
    profile: SshProfile,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
) {
    Card(
        Modifier
            .fillMaxWidth()
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onSelect),
    ) {
        Row(
            Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onSelect, enabled = enabled)
            Column(Modifier.weight(1f)) {
                Text(profile.displayName, style = MaterialTheme.typography.bodyLarge)
                Text(
                    "${profile.username}@${profile.host}:${profile.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            TextButton(onClick = onEdit, enabled = enabled) { Text("Ubah") }
        }
    }
}

@Composable
private fun HostKeyDialog(
    title: String,
    body: String,
    detail: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(body, style = MaterialTheme.typography.bodyMedium)
                SelectionContainer {
                    Text(detail, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
            }
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirmLabel) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Batal") } },
    )
}

private fun keyFileSuffix(keyType: String): String = when {
    keyType.contains("ed25519", ignoreCase = true) -> "ed25519"
    keyType.contains("ecdsa", ignoreCase = true) -> "ecdsa"
    keyType.contains("rsa", ignoreCase = true) -> "rsa"
    else -> "ed25519"
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = bytes / 1024.0
    var i = 0
    while (value >= 1024 && i < units.lastIndex) {
        value /= 1024
        i++
    }
    return String.format(Locale.US, "%.1f %s", value, units[i])
}

private fun formatDuration(millis: Long): String {
    val total = (millis / 1000).coerceAtLeast(0)
    return String.format(Locale.US, "%02d:%02d:%02d", total / 3600, (total % 3600) / 60, total % 60)
}
