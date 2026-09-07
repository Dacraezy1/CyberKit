package com.cyberkit.app.ui.screens.labs

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.labs.SecurityLab
import com.cyberkit.app.labs.SecurityLabRepository
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.SectionHeader

@Composable
fun LabsScreen() {
    var selectedLab by remember { mutableStateOf<SecurityLab?>(null) }

    if (selectedLab != null) {
        LabDetailView(lab = selectedLab!!, onBack = { selectedLab = null })
    } else {
        LabListView(onSelect = { selectedLab = it })
    }
}

@Composable
private fun LabListView(onSelect: (SecurityLab) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Cybersecurity Labs",
            subtitle = "Safe offline educational simulations and concept masteries",
            icon = Icons.Default.MenuBook
        )

        for (lab in SecurityLabRepository.LABS) {
            CyberCard(
                modifier = Modifier.fillMaxWidth(),
                onClick = { onSelect(lab) }
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(CyberSurfaceDark)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(lab.category, fontSize = 11.sp, color = CyberCyan, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                    }
                    Text(lab.difficulty, fontSize = 11.sp, color = if (lab.difficulty == "Advanced") SeverityCritical else CyberGreen)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(lab.title, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextPrimaryDark)
                Spacer(modifier = Modifier.height(4.dp))
                Text(lab.description, fontSize = 13.sp, color = TextSecondaryDark)
            }
        }
    }
}

@Composable
private fun LabDetailView(lab: SecurityLab, onBack: () -> Unit) {
    var selectedOption by remember { mutableStateOf<Int?>(null) }
    var submitted by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = CyberCyan)
            }
            Text(lab.title, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimaryDark)
        }

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Text("CONCEPTUAL OVERVIEW", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = CyberCyan, fontFamily = FontFamily.Monospace)
            Spacer(modifier = Modifier.height(6.dp))
            Text(lab.conceptSummary, fontSize = 13.sp, color = TextPrimaryDark, lineHeight = 18.sp)
        }

        CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberCyan.copy(alpha = 0.5f)) {
            Text("INTERACTIVE CHALLENGE", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = CyberCyan, fontFamily = FontFamily.Monospace)
            Spacer(modifier = Modifier.height(6.dp))
            Text(lab.challengePrompt, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimaryDark)

            Spacer(modifier = Modifier.height(12.dp))
            lab.options.forEachIndexed { index, option ->
                val isSelected = selectedOption == index
                val isCorrect = index == lab.correctIndex
                val btnColor = when {
                    !submitted && isSelected -> CyberCyan.copy(alpha = 0.2f)
                    submitted && isCorrect -> CyberGreen.copy(alpha = 0.2f)
                    submitted && isSelected && !isCorrect -> SeverityCritical.copy(alpha = 0.2f)
                    else -> CyberSurfaceDark
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(btnColor)
                        .clickable(enabled = !submitted) { selectedOption = index }
                        .padding(12.dp)
                ) {
                    Text(option, fontSize = 13.sp, color = TextPrimaryDark)
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            if (!submitted) {
                Button(
                    onClick = { if (selectedOption != null) submitted = true },
                    enabled = selectedOption != null,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
                ) {
                    Text("Submit Answer")
                }
            }
        }

        if (submitted) {
            val isCorrect = selectedOption == lab.correctIndex
            CyberCard(
                modifier = Modifier.fillMaxWidth(),
                borderColor = if (isCorrect) CyberGreen else SeverityCritical
            ) {
                Text(
                    text = if (isCorrect) "CORRECT ANSWER!" else "INCORRECT ANSWER",
                    fontWeight = FontWeight.Bold,
                    color = if (isCorrect) CyberGreen else SeverityCritical,
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(lab.explanation, fontSize = 13.sp, color = TextPrimaryDark)
                Spacer(modifier = Modifier.height(10.dp))
                Text("Defensive Takeaway:", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 12.sp)
                Text(lab.defensiveTakeaway, fontSize = 12.sp, color = CyberGreen)
            }
        }
    }
}
