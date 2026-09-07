package com.cyberkit.app.reports

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.FindingSeverity
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ReportGenerator {

    private fun formatDate(timestamp: Long): String {
        return SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date(timestamp))
    }

    fun exportToJson(summary: AssessmentSummary): String {
        val root = JSONObject()
        root.put("title", summary.title)
        root.put("target", summary.target)
        root.put("module", summary.module)
        root.put("securityScore", summary.score)
        root.put("timestamp", summary.timestamp)
        root.put("formattedDate", formatDate(summary.timestamp))

        val meta = JSONObject()
        for ((k, v) in summary.metadata) {
            meta.put(k, v)
        }
        root.put("metadata", meta)

        val findingsArray = JSONArray()
        for (f in summary.findings) {
            val fo = JSONObject()
            fo.put("id", f.id)
            fo.put("severity", f.severity.name)
            fo.put("title", f.title)
            fo.put("description", f.description)
            fo.put("evidence", f.evidence)
            fo.put("target", f.target)
            fo.put("module", f.module)
            fo.put("remediation", f.remediation)
            fo.put("confidence", f.confidence.name)
            fo.put("timestamp", f.timestamp)
            findingsArray.put(fo)
        }
        root.put("findings", findingsArray)

        return root.toString(2)
    }

    fun exportToCsv(summary: AssessmentSummary): String {
        val sb = StringBuilder()
        sb.append("Severity,Title,Target,Module,Confidence,Description,Evidence,Remediation\n")
        for (f in summary.findings) {
            sb.append("\"${escapeCsv(f.severity.name)}\",")
            sb.append("\"${escapeCsv(f.title)}\",")
            sb.append("\"${escapeCsv(f.target)}\",")
            sb.append("\"${escapeCsv(f.module)}\",")
            sb.append("\"${escapeCsv(f.confidence.name)}\",")
            sb.append("\"${escapeCsv(f.description)}\",")
            sb.append("\"${escapeCsv(f.evidence)}\",")
            sb.append("\"${escapeCsv(f.remediation)}\"\n")
        }
        return sb.toString()
    }

    private fun escapeCsv(value: String): String {
        return value.replace("\"", "\"\"").replace("\n", " ").replace("\r", "")
    }

    fun exportToTxt(summary: AssessmentSummary): String {
        val sb = StringBuilder()
        sb.append("================================================================================\n")
        sb.append("                       CYBERKIT SECURITY ASSESSMENT REPORT                      \n")
        sb.append("================================================================================\n\n")
        sb.append("Title:         ${summary.title}\n")
        sb.append("Target:        ${summary.target}\n")
        sb.append("Module:        ${summary.module}\n")
        sb.append("Security Score: ${summary.score} / 100\n")
        sb.append("Date:          ${formatDate(summary.timestamp)}\n")
        sb.append("Total Findings: ${summary.findings.size} (Critical: ${summary.criticalCount}, High: ${summary.highCount}, Med: ${summary.mediumCount}, Low: ${summary.lowCount}, Info: ${summary.infoCount})\n\n")

        if (summary.metadata.isNotEmpty()) {
            sb.append("--- ASSESSMENT METADATA ---\n")
            for ((k, v) in summary.metadata) {
                sb.append("  * $k: $v\n")
            }
            sb.append("\n")
        }

        sb.append("--- DETAILED FINDINGS ---\n\n")
        if (summary.findings.isEmpty()) {
            sb.append("No security anomalies or findings reported.\n")
        } else {
            summary.findings.forEachIndexed { idx, f ->
                sb.append("[${idx + 1}] [${f.severity}] ${f.title}\n")
                sb.append("    Target:      ${f.target}\n")
                sb.append("    Module:      ${f.module}\n")
                sb.append("    Confidence:  ${f.confidence}\n")
                sb.append("    Description: ${f.description}\n")
                if (f.evidence.isNotBlank()) {
                    sb.append("    Evidence:    ${f.evidence}\n")
                }
                if (f.remediation.isNotBlank()) {
                    sb.append("    Remediation: ${f.remediation}\n")
                }
                sb.append("\n")
            }
        }

        sb.append("================================================================================\n")
        sb.append("Generated offline by CyberKit Mobile Cybersecurity Toolkit.\n")
        sb.append("Assessment performed for authorized testing only.\n")
        return sb.toString()
    }

    fun exportToHtml(summary: AssessmentSummary): String {
        val dateStr = formatDate(summary.timestamp)
        val scoreColor = when {
            summary.score >= 80 -> "#00E676"
            summary.score >= 60 -> "#FFD600"
            summary.score >= 40 -> "#FF6D00"
            else -> "#FF1744"
        }

        val findingsRows = StringBuilder()
        for (f in summary.findings) {
            val badgeColor = when (f.severity) {
                FindingSeverity.CRITICAL -> "#FF1744"
                FindingSeverity.HIGH -> "#FF6D00"
                FindingSeverity.MEDIUM -> "#FFD600"
                FindingSeverity.LOW -> "#00E5FF"
                FindingSeverity.INFO -> "#00E676"
            }
            val badgeText = if (f.severity == FindingSeverity.MEDIUM) "#000" else "#FFF"

            findingsRows.append("""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="badge" style="background-color: $badgeColor; color: $badgeText;">${f.severity}</span>
                        <span class="finding-title">${escapeHtml(f.title)}</span>
                    </div>
                    <div class="finding-meta">Target: <b>${escapeHtml(f.target)}</b> &bull; Module: ${escapeHtml(f.module)} &bull; Confidence: ${f.confidence}</div>
                    <div class="finding-desc">${escapeHtml(f.description)}</div>
                    ${if (f.evidence.isNotBlank()) "<div class='finding-evidence'><b>Evidence:</b> <code>${escapeHtml(f.evidence)}</code></div>" else ""}
                    ${if (f.remediation.isNotBlank()) "<div class='finding-remediation'><b>Remediation:</b> ${escapeHtml(f.remediation)}</div>" else ""}
                </div>
            """.trimIndent())
        }

        val metadataItems = StringBuilder()
        for ((k, v) in summary.metadata) {
            metadataItems.append("<li><b>${escapeHtml(k)}:</b> ${escapeHtml(v)}</li>")
        }

        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${escapeHtml(summary.title)} - CyberKit Report</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background-color: #0B0F19;
                        color: #E2E8F0;
                        margin: 0;
                        padding: 24px;
                        line-height: 1.6;
                    }
                    .container { max-width: 900px; margin: 0 auto; }
                    .header {
                        border-bottom: 2px solid #1E293B;
                        padding-bottom: 16px;
                        margin-bottom: 24px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .header h1 { margin: 0; font-size: 24px; color: #00E5FF; }
                    .header .brand { color: #94A3B8; font-size: 14px; }
                    .summary-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 16px;
                        margin-bottom: 24px;
                    }
                    .card {
                        background-color: #131B2E;
                        border: 1px solid #1E293B;
                        border-radius: 8px;
                        padding: 16px;
                    }
                    .score-num { font-size: 36px; font-weight: bold; color: $scoreColor; }
                    .badge {
                        display: inline-block;
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-size: 12px;
                        font-weight: bold;
                        text-transform: uppercase;
                    }
                    .finding-card {
                        background-color: #131B2E;
                        border: 1px solid #1E293B;
                        border-radius: 8px;
                        padding: 16px;
                        margin-bottom: 16px;
                    }
                    .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
                    .finding-title { font-size: 16px; font-weight: 600; color: #F1F5F9; }
                    .finding-meta { font-size: 13px; color: #94A3B8; margin-bottom: 8px; }
                    .finding-desc { margin-bottom: 10px; }
                    .finding-evidence { background: #0B0F19; padding: 8px 12px; border-radius: 4px; margin-bottom: 8px; border-left: 3px solid #00E5FF; }
                    .finding-remediation { background: #0F2027; padding: 8px 12px; border-radius: 4px; border-left: 3px solid #00E676; }
                    code { color: #00E5FF; font-family: monospace; }
                    ul { padding-left: 20px; }
                    .footer { text-align: center; color: #64748B; font-size: 12px; margin-top: 40px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div>
                            <h1>${escapeHtml(summary.title)}</h1>
                            <div class="brand">CyberKit Authorized Cybersecurity Assessment</div>
                        </div>
                        <div style="text-align: right; font-size: 13px; color: #94A3B8;">
                            $dateStr
                        </div>
                    </div>

                    <div class="summary-grid">
                        <div class="card">
                            <div style="color: #94A3B8; font-size: 13px;">SECURITY SCORE</div>
                            <div class="score-num">${summary.score}<span style="font-size: 18px; color: #94A3B8;"> / 100</span></div>
                        </div>
                        <div class="card">
                            <div style="color: #94A3B8; font-size: 13px;">FINDINGS SUMMARY</div>
                            <div style="margin-top: 8px; font-size: 14px;">
                                <span style="color: #FF1744; font-weight: bold;">Critical: ${summary.criticalCount}</span> &bull; 
                                <span style="color: #FF6D00; font-weight: bold;">High: ${summary.highCount}</span> &bull; 
                                <span style="color: #FFD600; font-weight: bold;">Med: ${summary.mediumCount}</span> &bull; 
                                <span style="color: #00E5FF; font-weight: bold;">Low: ${summary.lowCount}</span>
                            </div>
                        </div>
                        <div class="card">
                            <div style="color: #94A3B8; font-size: 13px;">TARGET INFO</div>
                            <div style="margin-top: 8px; font-size: 14px;">
                                <b>${escapeHtml(summary.target)}</b><br>
                                <span style="color: #94A3B8;">${escapeHtml(summary.module)}</span>
                            </div>
                        </div>
                    </div>

                    ${if (summary.metadata.isNotEmpty()) """
                    <div class="card" style="margin-bottom: 24px;">
                        <h3 style="margin-top: 0; color: #00E5FF; font-size: 16px;">Assessment Metadata</h3>
                        <ul>$metadataItems</ul>
                    </div>
                    """.trimIndent() else ""}

                    <h2 style="color: #F1F5F9; font-size: 18px; margin-bottom: 16px;">Detailed Assessment Findings (${summary.findings.size})</h2>
                    $findingsRows

                    <div class="footer">
                        Generated locally on Android via CyberKit. Confidential Security Assessment.
                    </div>
                </div>
            </body>
            </html>
        """.trimIndent()
    }

    private fun escapeHtml(text: String): String {
        return text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    }
}
