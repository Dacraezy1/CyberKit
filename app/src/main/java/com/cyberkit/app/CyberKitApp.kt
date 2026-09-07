package com.cyberkit.app

import android.app.Application
import com.cyberkit.app.core.database.CyberKitDatabase

class CyberKitApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Initialize database instance
        CyberKitDatabase.getDatabase(this)
    }
}
