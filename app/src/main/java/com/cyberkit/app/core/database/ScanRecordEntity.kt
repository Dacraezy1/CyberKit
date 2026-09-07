package com.cyberkit.app.core.database

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

@Entity(tableName = "scan_records")
data class ScanRecordEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val title: String,
    val module: String,
    val target: String,
    val score: Int,
    val timestamp: Long,
    val findingsJson: String,
    val metadataJson: String
) {
    fun toAssessmentSummary(): AssessmentSummary {
        val findingsList = mutableListOf<Finding>()
        try {
            val array = JSONArray(findingsJson)
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                findingsList.add(
                    Finding(
                        id = obj.optString("id", UUID.randomUUID().toString()),
                        severity = FindingSeverity.valueOf(obj.optString("severity", "INFO")),
                        title = obj.optString("title", ""),
                        description = obj.optString("description", ""),
                        evidence = obj.optString("evidence", ""),
                        target = obj.optString("target", target),
                        module = obj.optString("module", module),
                        remediation = obj.optString("remediation", ""),
                        confidence = FindingConfidence.valueOf(obj.optString("confidence", "HIGH")),
                        timestamp = obj.optLong("timestamp", timestamp)
                    )
                )
            }
        } catch (_: Exception) {}

        val metaMap = mutableMapOf<String, String>()
        try {
            val obj = JSONObject(metadataJson)
            val keys = obj.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                metaMap[key] = obj.getString(key)
            }
        } catch (_: Exception) {}

        return AssessmentSummary(
            title = title,
            target = target,
            module = module,
            score = score,
            findings = findingsList,
            metadata = metaMap,
            timestamp = timestamp
        )
    }

    companion object {
        fun fromAssessmentSummary(summary: AssessmentSummary, id: String = UUID.randomUUID().toString()): ScanRecordEntity {
            val jsonArray = JSONArray()
            for (f in summary.findings) {
                val obj = JSONObject()
                obj.put("id", f.id)
                obj.put("severity", f.severity.name)
                obj.put("title", f.title)
                obj.put("description", f.description)
                obj.put("evidence", f.evidence)
                obj.put("target", f.target)
                obj.put("module", f.module)
                obj.put("remediation", f.remediation)
                obj.put("confidence", f.confidence.name)
                obj.put("timestamp", f.timestamp)
                jsonArray.put(obj)
            }

            val metaObj = JSONObject()
            for ((k, v) in summary.metadata) {
                metaObj.put(k, v)
            }

            return ScanRecordEntity(
                id = id,
                title = summary.title,
                module = summary.module,
                target = summary.target,
                score = summary.score,
                timestamp = summary.timestamp,
                findingsJson = jsonArray.toString(),
                metadataJson = metaObj.toString()
            )
        }
    }
}
