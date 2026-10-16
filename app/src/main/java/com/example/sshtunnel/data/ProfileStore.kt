package com.example.sshtunnel.data

import android.content.Context
import android.util.Log
import org.json.JSONArray

/**
 * Penyimpanan profil SSH. Seluruh daftar profil dienkripsi sebagai satu blob ([SecretBox]).
 * Hanya id profil terpilih yang disimpan polos (bukan rahasia).
 */
class ProfileStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("profiles", Context.MODE_PRIVATE)

    var selectedId: String?
        get() = prefs.getString(KEY_SELECTED, null)
        set(value) {
            prefs.edit().putString(KEY_SELECTED, value).apply()
        }

    @Synchronized
    fun load(): List<SshProfile> {
        val blob = prefs.getString(KEY_DATA, null) ?: return emptyList()
        return try {
            val array = JSONArray(SecretBox.decrypt(blob))
            List(array.length()) { SshProfile.fromJson(array.getJSONObject(it)) }
        } catch (e: Exception) {
            // Kunci Keystore hilang (mis. setelah reset/restore perangkat) atau data rusak.
            Log.e(TAG, "Gagal membaca profil: ${e.message}")
            emptyList()
        }
    }

    @Synchronized
    fun get(id: String): SshProfile? = load().firstOrNull { it.id == id }

    @Synchronized
    fun upsert(profile: SshProfile) {
        val list = load().toMutableList()
        val index = list.indexOfFirst { it.id == profile.id }
        if (index >= 0) list[index] = profile else list += profile
        save(list)
    }

    @Synchronized
    fun delete(id: String) {
        save(load().filterNot { it.id == id })
        if (selectedId == id) selectedId = null
    }

    /** Menyimpan fingerprint host key yang dipercaya pengguna ke profil. */
    @Synchronized
    fun trustHostKey(id: String, fingerprint: String) {
        val profile = get(id) ?: return
        upsert(profile.copy(trustedHostKey = fingerprint))
    }

    private fun save(list: List<SshProfile>) {
        val array = JSONArray()
        list.forEach { array.put(it.toJson()) }
        prefs.edit().putString(KEY_DATA, SecretBox.encrypt(array.toString())).apply()
    }

    private companion object {
        const val TAG = "ProfileStore"
        const val KEY_DATA = "data"
        const val KEY_SELECTED = "selected"
    }
}
