package com.example.sshtunnel.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Status tunnel yang dipakai bersama oleh service (penulis) dan UI (pembaca).
 * Service dan UI berjalan di satu proses, jadi cukup berupa singleton.
 */
object TunnelManager {
    private val _state = MutableStateFlow<TunnelState>(TunnelState.Disconnected)
    val state: StateFlow<TunnelState> = _state.asStateFlow()

    private val _traffic = MutableStateFlow(Traffic())
    val traffic: StateFlow<Traffic> = _traffic.asStateFlow()

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log.asStateFlow()

    val isActive: Boolean
        get() = when (_state.value) {
            is TunnelState.Connecting, is TunnelState.Connected, is TunnelState.Reconnecting -> true
            is TunnelState.Disconnected, is TunnelState.Failed -> false
        }

    fun setState(newState: TunnelState) {
        _state.value = newState
    }

    fun setTraffic(traffic: Traffic) {
        _traffic.value = traffic
    }

    fun log(message: String) {
        val line = "${SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())}  $message"
        _log.update { (it + line).takeLast(MAX_LOG_LINES) }
    }

    fun clearLog() {
        _log.value = emptyList()
    }

    private const val MAX_LOG_LINES = 200
}
