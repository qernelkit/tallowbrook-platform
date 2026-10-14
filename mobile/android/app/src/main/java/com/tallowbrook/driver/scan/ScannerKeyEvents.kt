package com.tallowbrook.driver.scan

import android.view.KeyEvent

/** Wired ring scanners type the barcode as key presses and finish with Enter. */
class ScannerKeyEvents(private val onBarcode: (String) -> Unit) {

    private val buffer = StringBuilder()

    fun onKeyEvent(event: KeyEvent): Boolean {
        if (event.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_UP) {
            if (buffer.isNotEmpty()) {
                onBarcode(buffer.toString())
                buffer.clear()
            }
            return true
        }
        if (event.action != KeyEvent.ACTION_DOWN) return false
        val ch = event.unicodeChar
        if (ch == 0) return false
        buffer.append(ch.toChar())
        return true
    }
}
