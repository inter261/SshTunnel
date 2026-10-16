# SSH Tunnel (Android, Kotlin)

Aplikasi VPN berbasis SSH: semua trafik perangkat dikirim lewat satu koneksi SSH ke server Anda.

```
aplikasi → TUN → tun2socks (native) → SOCKS5 lokal (127.0.0.1, auth acak) → SSH direct-tcpip → server
```

## Status build dan pengujian (baca dulu)

| Bagian | Status |
|---|---|
| `Socks5Server` (auth, CONNECT, UDP-DNS, half-close, 1 MB data, close) | **Diuji**: 17 dari 17 tes lulus di JVM |
| Library native tun2socks | Sumber asli hev-socks5-tunnel 2.19.0, nama JNI dan format config dicocokkan dengan kodenya. **Belum dikompilasi.** |
| Sisanya (sshj, VpnService, Compose, Keystore) | **Belum dikompilasi dan belum dijalankan.** Kemungkinan ada error kompilasi kecil atau bug saat uji pertama di perangkat. |

## Cara build

Prasyarat: Android Studio (Ladybug atau lebih baru) dengan **NDK** dan **CMake/SDK Platform 35** terpasang (SDK Manager).

1. Buka folder ini di Android Studio, tunggu sync Gradle.
2. Run di perangkat fisik (emulator tidak ideal untuk VPN). Atau di terminal: `./gradlew assembleDebug`
3. APK ada di `app/build/outputs/apk/debug/`.

Tanpa Android Studio: dorong folder ini ke repo GitHub, lalu jalankan workflow **Build APK** (tab Actions). APK-nya muncul sebagai artifact.

## Pemakaian

1. **Profil baru**: isi host, port, username, lalu password atau private key (OpenSSH/PEM/PPK).
2. **Sambung**. Pertama kali, aplikasi menampilkan fingerprint host key. Cocokkan dengan server Anda
   (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), baru percayai.
3. Jika fingerprint berubah di kemudian hari, aplikasi memperingatkan (kemungkinan MITM) dan tidak sambung otomatis.

## Syarat di server

- `AllowTcpForwarding yes` di `sshd_config` (default-nya sudah yes).
- Server dapat menjangkau DNS di profil (default `8.8.8.8`). Cek ini dilakukan saat sambung, dengan pesan error jelas bila gagal.

## Perilaku penting

- **Tanpa DNS leak**: query DNS UDP port 53 diubah jadi DNS-over-TCP di dalam tunnel, ke resolver di profil.
- **IPv6 ikut masuk tunnel** (tidak bocor lewat jaringan langsung), tetapi hanya bisa dipakai jika server SSH punya konektivitas IPv6.
- **UDP selain DNS tidak didukung** (SSH tidak punya UDP). Aplikasi berbasis QUIC/HTTP3 otomatis fallback ke TCP. Panggilan suara/video (WebRTC) dan game UDP kemungkinan tidak jalan.
- **Reconnect otomatis**: SSH putus atau ganti jaringan (Wi-Fi ↔ seluler) → hanya koneksi SSH yang diganti, antarmuka VPN tetap. Selama itu koneksi baru ditolak, bukan bocor ke jaringan langsung.
- **Port SOCKS lokal** hanya di 127.0.0.1 dengan username/password acak per sesi.
- **Kredensial** disimpan terenkripsi AES-256-GCM dengan kunci di Android Keystore. Jika perangkat direset, profil tidak bisa dibaca lagi.
- Matikan optimasi baterai untuk aplikasi ini bila koneksi sering terputus di latar belakang.

## Struktur

```
app/src/main/java/com/example/sshtunnel/
  core/   Socks5Server, SshEngine (sshj), TunnelManager (state), TunnelState
  vpn/    TunnelVpnService, TunnelSession (orkestrasi+reconnect), Tun2Socks, NetworkWatcher
  data/   SshProfile, ProfileStore, SecretBox (Keystore)
  ui/     MainScreen, ProfileEditorScreen (Compose)
app/src/main/jni/hev-socks5-tunnel/   library native (MIT)
```

## Menambah V2Ray nanti

`TunnelSession` sudah memisahkan tiga lapisan. Untuk V2Ray, ganti lapisan "SSH + Socks5Server" dengan core Xray/v2ray
yang membuka SOCKS5 lokal, lalu pakai ulang `Tun2Socks` dan VpnService apa adanya. Langkah wajar berikutnya:
ekstrak antarmuka `TunnelEngine { start(); stop(); socksPort }`.

## Lisensi

hev-socks5-tunnel: MIT (lihat `HEV_SOCKS5_TUNNEL_LICENSE`). sshj: Apache-2.0. BouncyCastle: MIT.
Gunakan hanya pada server yang Anda miliki atau berwenang untuk memakainya.
