package com.tallowbrook.driver.ui

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.view.KeyEvent
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.tallowbrook.driver.data.RouteManifest
import com.tallowbrook.driver.data.Stop
import com.tallowbrook.driver.scan.ScannerKeyEvents

/**
 * The stop list for today's route, with scans from a wired or paired scanner marking stops done.
 */
class RouteActivity : Activity() {

    private lateinit var list: LinearLayout
    private var manifest: RouteManifest? = null
    private val scanner = ScannerKeyEvents { barcode -> onBarcode(barcode) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        setContentView(ScrollView(this).apply { addView(list) })
        title = "Today's route"
    }

    fun show(route: RouteManifest) {
        manifest = route
        list.removeAllViews()
        route.stops.forEachIndexed { index, stop -> list.addView(row(index, stop)) }
    }

    private fun row(index: Int, stop: Stop): TextView =
        TextView(this).apply {
            text = "${index + 1}. ${stop.addressLine}  (${stop.parcelIds.size})"
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 24, 32, 24)
            setTextColor(RouteColors.forStop(index))
            alpha = if (stop.done) 0.4f else 1f
        }

    private fun onBarcode(barcode: String) {
        val route = manifest ?: return
        val updated = route.markScanned(barcode)
        if (updated !== route) show(updated)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean =
        scanner.onKeyEvent(event) || super.dispatchKeyEvent(event)
}
