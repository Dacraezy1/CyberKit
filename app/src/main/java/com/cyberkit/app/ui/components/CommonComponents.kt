package com.cyberkit.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingSeverity
import com.cyberkit.app.core.theme.*

@Composable
fun CyberCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    borderColor: Color = CyberCardBorder,
    backgroundColor: Color = CyberCardDark,
    content: @Composable ColumnScope.() -> Unit
) {
    val clickableModifier = if (onClick != null) modifier.clickable(onClick = onClick) else modifier

    Column(
        modifier = clickableModifier
            .clip(RoundedCornerShape(12.dp))
            .background(backgroundColor)
            .border(1.dp, borderColor, RoundedCornerShape(12.dp))
            .padding(16.dp),
        content = content
    )
}

@Composable
fun SeverityBadge(severity: FindingSeverity) {
    val (bgColor, textColor) = when (severity) {
        FindingSeverity.CRITICAL -> Pair(SeverityCritical, Color.White)
        FindingSeverity.HIGH -> Pair(SeverityHigh, Color.White)
        FindingSeverity.MEDIUM -> Pair(SeverityMedium, Color.Black)
        FindingSeverity.LOW -> Pair(SeverityLow, Color.Black)
        FindingSeverity.INFO -> Pair(SeverityInfo, Color.Black)
    }

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(4.dp))
            .background(bgColor)
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = severity.name,
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun ScoreBadge(score: Int) {
    val color = when {
        score >= 80 -> CyberGreen
        score >= 60 -> CyberAmber
        score >= 40 -> SeverityHigh
        else -> SeverityCritical
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = "$score",
            fontSize = 28.sp,
            fontWeight = FontWeight.ExtraBold,
            color = color
        )
        Text(
            text = "/100",
            fontSize = 14.sp,
            color = TextMutedDark
        )
    }
}

@Composable
fun SectionHeader(
    title: String,
    subtitle: String? = null,
    icon: ImageVector? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = CyberCyan,
                modifier = Modifier.size(22.dp)
            )
        }
        Column {
            Text(
                text = title,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimaryDark
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    fontSize = 13.sp,
                    color = TextSecondaryDark
                )
            }
        }
    }
}

@Composable
fun FindingCard(finding: Finding) {
    CyberCard(
        modifier = Modifier.fillMaxWidth(),
        borderColor = when (finding.severity) {
            FindingSeverity.CRITICAL -> SeverityCritical.copy(alpha = 0.5f)
            FindingSeverity.HIGH -> SeverityHigh.copy(alpha = 0.5f)
            else -> CyberCardBorder
        }
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            SeverityBadge(severity = finding.severity)
            Text(
                text = finding.module,
                fontSize = 12.sp,
                color = CyberCyan,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = finding.title,
            fontSize = 15.sp,
            fontWeight = FontWeight.SemiBold,
            color = TextPrimaryDark
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = finding.description,
            fontSize = 13.sp,
            color = TextSecondaryDark
        )
        if (finding.evidence.isNotBlank()) {
            Spacer(modifier = Modifier.height(8.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(6.dp))
                    .background(CyberBgDark)
                    .padding(8.dp)
            ) {
                Text(
                    text = "Evidence: ${finding.evidence}",
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    color = CyberCyan
                )
            }
        }
        if (finding.remediation.isNotBlank()) {
            Spacer(modifier = Modifier.height(8.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(6.dp))
                    .background(Color(0xFF0C241F))
                    .padding(8.dp)
            ) {
                Text(
                    text = "Remediation: ${finding.remediation}",
                    fontSize = 12.sp,
                    color = CyberGreen
                )
            }
        }
    }
}
