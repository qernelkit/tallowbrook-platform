package com.tallowbrook.driver.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View

/** Where the customer signs for the parcel with a finger. */
class SignaturePadView(context: Context, attrs: AttributeSet?) : View(context, attrs) {

    private val strokes = mutableListOf<Path>()
    private var current: Path? = null
    private val ink =
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = 6f
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
            color = Color.BLACK
        }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN ->
                current = Path().apply { moveTo(event.x, event.y) }.also { strokes += it }
            MotionEvent.ACTION_MOVE -> current?.lineTo(event.x, event.y)
            MotionEvent.ACTION_UP,
            MotionEvent.ACTION_CANCEL -> current = null
            else -> return false
        }
        invalidate()
        return true
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        strokes.forEach { canvas.drawPath(it, ink) }
    }

    fun isBlank(): Boolean = strokes.isEmpty()

    fun clear() {
        strokes.clear()
        current = null
        invalidate()
    }

    fun signatureBitmap(): Bitmap {
        val bitmap =
            Bitmap.createBitmap(
                width.coerceAtLeast(1),
                height.coerceAtLeast(1),
                Bitmap.Config.ARGB_8888,
            )
        val canvas = Canvas(bitmap)
        canvas.drawColor(Color.WHITE)
        strokes.forEach { canvas.drawPath(it, ink) }
        return bitmap
    }
}
