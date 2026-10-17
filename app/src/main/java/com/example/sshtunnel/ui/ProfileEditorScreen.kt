package com.example.sshtunnel.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.sshtunnel.data.AuthType
import com.example.sshtunnel.data.SshProfile

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileEditorScreen(
    initial: SshProfile,
    isNew: Boolean,
    onSave: (SshProfile) -> Unit,
    onDelete: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current

    var name by remember { mutableStateOf(initial.name) }
    var host by remember { mutableStateOf(initial.host) }
    var port by remember { mutableStateOf(initial.port.toString()) }
    var username by remember { mutableStateOf(initial.username) }
    var authType by remember { mutableStateOf(initial.authType) }
    var password by remember { mutableStateOf(initial.password) }
    var privateKey by remember { mutableStateOf(initial.privateKey) }
    var passphrase by remember { mutableStateOf(initial.keyPassphrase) }
    var compression by remember { mutableStateOf(initial.compression) }
    var keepAlive by remember { mutableStateOf(initial.keepAliveSeconds.toString()) }
    var dns by remember { mutableStateOf(initial.dnsServer) }
    var mode by remember { mutableStateOf(TransportMode.from(initial)) }
    var sni by remember { mutableStateOf(initial.sni) }
    var payload by remember { mutableStateOf(initial.payload) }
    var proxyHost by remember { mutableStateOf(initial.proxyHost) }
    var proxyPort by remember { mutableStateOf(initial.proxyPort.toString()) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }

    BackHandler(onBack = onCancel)

    // Memilih file private key: isinya dibaca ke dalam form, tidak disalin ke tempat lain.
    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        try {
            val stream = context.contentResolver.openInputStream(uri)
            // Dibatasi MAX_KEY_BYTES + 1 supaya file besar tidak memenuhi memori (readNBytes baru ada di API 33).
            val bytes = stream?.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                while (out.size() <= MAX_KEY_BYTES) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
            when {
                bytes == null -> error = "File tidak bisa dibuka"
                bytes.size > MAX_KEY_BYTES -> error = "File terlalu besar untuk private key"
                else -> {
                    privateKey = String(bytes, Charsets.UTF_8)
                    error = null
                }
            }
        } catch (e: Exception) {
            error = "Gagal membaca file: ${e.message}"
        }
    }

    fun save() {
        val candidate = initial.copy(
            name = name.trim(),
            host = host.trim(),
            port = port.trim().toIntOrNull() ?: -1,
            username = username.trim(),
            authType = authType,
            password = password,
            // Key OpenSSH wajib diakhiri baris baru; ditambahkan di sini kalau hilang saat copy-paste.
            privateKey = privateKey.trim().let { if (it.isEmpty()) "" else it + "\n" },
            keyPassphrase = passphrase,
            compression = compression,
            keepAliveSeconds = keepAlive.trim().toIntOrNull() ?: -1,
            dnsServer = dns.trim(),
            useTls = mode.usesTls,
            sni = if (mode.usesTls) sni.trim() else "",
            payload = if (mode.usesPayload) payload else "", // baris kosong di akhir payload itu penting, jangan di-trim
            proxyHost = if (mode.usesPayload) proxyHost.trim() else "",
            proxyPort = proxyPort.trim().toIntOrNull() ?: 8080,
            // Server berubah = fingerprint lama tidak berlaku lagi.
            trustedHostKey = if (host.trim() == initial.host && port.trim().toIntOrNull() == initial.port) {
                initial.trustedHostKey
            } else {
                ""
            },
        )
        val problem = candidate.validate()
        if (problem != null) {
            error = problem
            return
        }
        onSave(candidate)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (isNew) "Profil baru" else "Ubah profil") },
                navigationIcon = { TextButton(onClick = onCancel) { Text("Batal") } },
                actions = { TextButton(onClick = ::save) { Text("Simpan") } },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }

            OutlinedTextField(
                value = name, onValueChange = { name = it },
                label = { Text("Nama (opsional)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = host, onValueChange = { host = it },
                    label = { Text("Host / IP") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = port, onValueChange = { port = it.filter(Char::isDigit).take(5) },
                    label = { Text("Port") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(0.4f),
                )
            }
            OutlinedTextField(
                value = username, onValueChange = { username = it },
                label = { Text("Username") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Text("Metode login", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = authType == AuthType.PASSWORD,
                    onClick = { authType = AuthType.PASSWORD },
                    label = { Text("Password") },
                )
                FilterChip(
                    selected = authType == AuthType.PRIVATE_KEY,
                    onClick = { authType = AuthType.PRIVATE_KEY },
                    label = { Text("Private key") },
                )
            }

            if (authType == AuthType.PASSWORD) {
                OutlinedTextField(
                    value = password, onValueChange = { password = it },
                    label = { Text("Password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                OutlinedButton(onClick = { pickKey.launch(arrayOf("*/*")) }) { Text("Pilih file key …") }
                OutlinedTextField(
                    value = privateKey, onValueChange = { privateKey = it },
                    label = { Text("Isi private key (OpenSSH / PEM / PPK)") },
                    minLines = 4, maxLines = 8,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it },
                    label = { Text("Passphrase key (kosongkan jika tidak ada)") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Text("Koneksi ke server (transport)", style = MaterialTheme.typography.titleSmall)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TransportMode.entries.forEach { option ->
                    FilterChip(
                        selected = mode == option,
                        onClick = {
                            mode = option
                            // Isi payload contoh saat pertama memilih mode yang memakai payload.
                            if (option.usesPayload && payload.isBlank()) payload = PAYLOAD_WEBSOCKET
                        },
                        label = { Text(option.label) },
                    )
                }
            }
            Text(
                mode.hint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (mode.usesTls) {
                OutlinedTextField(
                    value = sni, onValueChange = { sni = it },
                    label = { Text("SNI (kosongkan = pakai host)") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (mode.usesPayload) {
                OutlinedTextField(
                    value = payload, onValueChange = { payload = it },
                    label = { Text("Payload") },
                    minLines = 3, maxLines = 8,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { payload = PAYLOAD_WEBSOCKET }) { Text("Contoh WebSocket") }
                    OutlinedButton(onClick = { payload = PAYLOAD_CONNECT }) { Text("Contoh CONNECT") }
                }
                Text(
                    "Placeholder: [host] [port] [host_port] [protocol] [crlf] [cr] [lf] [split] " +
                        "([split] = kirim bagian berikutnya di paket terpisah).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = proxyHost, onValueChange = { proxyHost = it },
                        label = { Text("Proxy (opsional)") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = proxyPort, onValueChange = { proxyPort = it.filter(Char::isDigit).take(5) },
                        label = { Text("Port") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(0.4f),
                    )
                }
            }

            Text("Lanjutan", style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = dns, onValueChange = { dns = it },
                label = { Text("DNS server (dijangkau lewat tunnel)") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = keepAlive, onValueChange = { keepAlive = it.filter(Char::isDigit).take(3) },
                label = { Text("Keepalive (detik)") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Kompresi SSH", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Berguna di koneksi lambat; menambah beban CPU.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = compression, onCheckedChange = { compression = it })
            }

            if (initial.trustedHostKey.isNotBlank()) {
                Text("Host key dipercaya", style = MaterialTheme.typography.titleSmall)
                Text(
                    initial.trustedHostKey,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Button(onClick = ::save, modifier = Modifier.fillMaxWidth()) { Text("Simpan") }
            if (!isNew) {
                TextButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("Hapus profil", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Hapus profil?") },
            text = { Text("Profil “${initial.displayName}” beserta kredensialnya akan dihapus dari perangkat.") },
            confirmButton = { TextButton(onClick = onDelete) { Text("Hapus") } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Batal") } },
        )
    }
}

private const val MAX_KEY_BYTES = 64 * 1024

private const val PAYLOAD_WEBSOCKET =
    "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
private const val PAYLOAD_CONNECT =
    "CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]"

/** Pilihan cepat cara menjangkau server SSH. Menentukan field mana yang tampil dan dipakai. */
private enum class TransportMode(val label: String, val usesTls: Boolean, val usesPayload: Boolean, val hint: String) {
    DIRECT("Langsung", false, false, "Koneksi SSH biasa ke host dan port di atas."),
    TLS("SSL/TLS", true, false, "SSH dibungkus TLS (seperti stunnel) dengan SNI yang bisa diatur. Server harus melayani TLS di port itu (biasanya 443). Port 80 umumnya HTTP polos: pakai Payload HTTP. Isi SNI dengan nama domain, bukan IP."),
    PAYLOAD("Payload HTTP", false, true, "Mengirim teks HTTP dulu, menunggu balasan (101/200), lalu SSH berjalan di koneksi yang sama."),
    TLS_PAYLOAD("SSL + Payload", true, true, "TLS dengan SNI sendiri, lalu payload HTTP di dalamnya, lalu SSH.");

    companion object {
        fun from(profile: SshProfile) = when {
            profile.useTls && profile.payload.isNotBlank() -> TLS_PAYLOAD
            profile.useTls -> TLS
            profile.payload.isNotBlank() -> PAYLOAD
            else -> DIRECT
        }
    }
}
