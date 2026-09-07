package com.cyberkit.app.ui.screens.reports

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.database.CyberKitDatabase
import com.cyberkit.app.core.database.ScanRecordEntity
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.reports.ReportGenerator
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.FindingCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ReportsScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val db = remember { CyberKitDatabase.getDatabase(context) }
    var searchQuery by remember { mutableStateOf("") }

    val scanRecords by remember(searchQuery) {
        if (searchQuery.isBlank()) {
            db.scanDao().getAllScans()
        } else {
            db.scanDao().searchScans(searchQuery)
        }
    }.collectAsState(initial = emptyList())

    var selectedRecord by remember { mutableStateOf<ScanRecordEntity?>(null) }
    var showExportDialog by remember { mutableStateOf(false) }

    if (selectedRecord != null) {
        // Detailed View
        val summary = remember(selectedRecord) { selectedRecord!!.toAssessmentSummary() }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(CyberBgDark)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = { selectedRecord = null }) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = CyberCyan)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { showExportDialog = true },
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Export")
                    }
                    IconButton(onClick = {
                        coroutineScope.launch {
                            db.scanDao().deleteScanById(selectedRecord!!.id)
                            selectedRecord = null
                        }
                    }) {
                        Icon(Icons.Default.Delete, contentDescription = "Delete", tint = SeverityCritical)
                    }
                }
            }

            CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(summary.title, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = TextPrimaryDark)
                        Text(summary.module, fontSize = 12.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                        Text(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(summary.timestamp)), fontSize = 11.sp, color = TextMutedDark)
                    }
                    ScoreBadge(score = summary.score)
                }
            }

            Text("FINDINGS (${summary.findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in summary.findings) {
                FindingCard(finding = f)
            }
        }

        if (showExportDialog) {
            ExportModal(
                context = context,
                summary = summary,
                onDismiss = { showExportDialog = false }
            )
        }
    } else {
        // List View
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(CyberBgDark)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            SectionHeader(
                title = "Security Reports & History",
                subtitle = "Local offline repository of completed security assessments",
                icon = Icons.Default.Assessment
            )

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                label = { Text("Search Assessments by Target or Title") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberCyan) }
            )

            if (scanRecords.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text("No security assessments recorded yet.", color = TextMutedDark)
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(scanRecords) { record ->
                        CyberCard(
                            modifier = Modifier.fillMaxWidth(),
                            onClick = { selectedRecord = record }
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(record.title, fontWeight = FontWeight.Bold, fontSize = 15.sp, color = TextPrimaryDark)
                                    Text("${record.module} &bull; ${record.target}", fontSize = 12.sp, color = TextSecondaryDark)
                                    Text(
                                        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(record.timestamp)),
                                        fontSize = 11.sp,
                                        color = TextMutedDark
                                    )
                                }
                                Text(
                                    text = "${record.score}/100",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                    color = if (record.score >= 80) CyberGreen else if (record.score >= 60) CyberAmber else SeverityCritical,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ExportModal(
    context: Context,
    summary: AssessmentSummary,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Export Assessment Report") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Select format to export or copy:")
                val formats = listOf("JSON", "HTML", "TXT", "CSV")
                for (fmt in formats) {
                    Button(
                        onClick = {
                            val content = when (fmt) {
                                "JSON" -> ReportGenerator.exportToJson(summary)
                                "HTML" -> ReportGenerator.exportToHtml(summary)
                                "TXT" -> ReportGenerator.exportToTxt(summary)
                                "CSV" -> ReportGenerator.exportToCsv(summary)
                                else -> ""
                            }
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("CyberKit Report", content))

                            // Share Intent
                            val sendIntent = Intent().apply {
                                action = Intent.ACTION_SEND
                                putExtra(Intent.EXTRA_TEXT, content)
                                type = "text/plain"
                            }
                            context.startActivity(Intent.createChooser(sendIntent, "Share CyberKit Report ($fmt)"))
                            onDismiss()
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberSurfaceDark, contentColor = CyberCyan)
                    ) {
                        Text("Export as $fmt")
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        }
    )
}
