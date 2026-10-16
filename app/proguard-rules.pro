# Aturan dasar jika isMinifyEnabled diaktifkan.

# JNI: kelas ini diregistrasi dari kode native (JNI_OnLoad -> RegisterNatives).
-keep class hev.htproxy.TProxyService { *; }

# sshj dan BouncyCastle memakai refleksi untuk memuat algoritma.
-keep class net.schmizz.** { *; }
-keep class com.hierynomus.** { *; }
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn net.schmizz.**
-dontwarn com.hierynomus.**
-dontwarn javax.naming.**
-dontwarn org.ietf.jgss.**
-dontwarn com.jcraft.jzlib.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn org.slf4j.**
