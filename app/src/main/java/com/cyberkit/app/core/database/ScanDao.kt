package com.cyberkit.app.core.database

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanDao {
    @Query("SELECT * FROM scan_records ORDER BY timestamp DESC")
    fun getAllScans(): Flow<List<ScanRecordEntity>>

    @Query("SELECT * FROM scan_records WHERE id = :id LIMIT 1")
    suspend fun getScanById(id: String): ScanRecordEntity?

    @Query("SELECT * FROM scan_records WHERE module = :module ORDER BY timestamp DESC")
    fun getScansByModule(module: String): Flow<List<ScanRecordEntity>>

    @Query("SELECT * FROM scan_records WHERE target LIKE '%' || :query || '%' OR title LIKE '%' || :query || '%' ORDER BY timestamp DESC")
    fun searchScans(query: String): Flow<List<ScanRecordEntity>>

    @Query("SELECT COUNT(*) FROM scan_records")
    fun getScanCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ScanRecordEntity)

    @Delete
    suspend fun deleteScan(scan: ScanRecordEntity)

    @Query("DELETE FROM scan_records WHERE id = :id")
    suspend fun deleteScanById(id: String)

    @Query("DELETE FROM scan_records")
    suspend fun deleteAllScans()
}
