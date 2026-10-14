package com.tallowbrook.driver

import android.app.Application
import android.util.Log
import com.tallowbrook.driver.net.ApiClient
import com.tallowbrook.driver.net.TlsProvider

class DriverApp : Application() {

    lateinit var api: ApiClient
        private set

    override fun onCreate() {
        super.onCreate()
        TlsProvider.install()
        api = ApiClient()
        Log.i(
            TAG,
            "Driver app started, version code ${packageManager.getPackageInfo(packageName, 0).longVersionCode}",
        )
    }

    companion object {
        private const val TAG = "DriverApp"
    }
}
