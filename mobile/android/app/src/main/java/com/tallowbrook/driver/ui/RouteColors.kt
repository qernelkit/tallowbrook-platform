package com.tallowbrook.driver.ui

/** Colours for stop markers on the route map, cycled in stop order. */
object RouteColors {
    val rainbow =
        intArrayOf(0xFFE53935.toInt(), 0xFFFB8C00.toInt(), 0xFFFDD835.toInt(), 0xFF43A047.toInt())

    fun forStop(index: Int): Int = rainbow[Math.floorMod(index, rainbow.size)]
}
