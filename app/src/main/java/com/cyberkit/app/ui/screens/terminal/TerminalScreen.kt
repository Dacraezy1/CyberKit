package com.cyberkit.app.ui.screens.terminal

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.theme.CyberBgDark
import com.cyberkit.app.core.theme.CyberCyan
import com.cyberkit.app.core.theme.CyberGreen
import com.cyberkit.app.core.theme.CyberSurfaceDark
import com.cyberkit.app.core.theme.TextMutedDark
import com.cyberkit.app.core.theme.TextPrimaryDark
import com.cyberkit.app.core.theme.TextSecondaryDark
import com.cyberkit.app.terminal.CyberKitTerminalEngine
import kotlinx.coroutines.launch

data class TerminalLine(val text: String, val isCommand: Boolean = false)

@Composable
fun TerminalScreen() {
    val coroutineScope = rememberCoroutineScope()
    val engine = remember { CyberKitTerminalEngine() }
    var inputCommand by remember { mutableStateOf("") }
    val lines = remember {
        mutableStateListOf(
            TerminalLine("CyberKit Workstation Shell v1.0.0 (Linux/Android non-root)"),
            TerminalLine("Type 'help' to list available tools and command syntax.\n")
        )
    }
    val listState = rememberLazyListState()

    fun runCommand(cmd: String) {
        if (cmd.isBlank()) return
        if (cmd.trim().equals("clear", ignoreCase = true)) {
            lines.clear()
            return
        }
        lines.add(TerminalLine("cyberkit> $cmd", isCommand = true))
        coroutineScope.launch {
            val output = engine.executeCommand(cmd)
            if (output.isNotBlank()) {
                lines.add(TerminalLine(output, isCommand = false))
            }
            listState.animateScrollToItem((lines.size - 1).coerceAtLeast(0))
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
            .padding(12.dp)
    ) {
        // Quick Command Chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            val quickChips = listOf("help", "netinfo", "subnet 192.168.1.0/24", "discover 192.168.1.0/24", "scan 127.0.0.1 22,80,443", "dns cloudflare.com", "tls google.com 443", "clear")
            for (qc in quickChips) {
                AssistChip(
                    onClick = {
                        inputCommand = qc
                        runCommand(qc)
                    },
                    label = { Text(qc.split(" ")[0], fontSize = 11.sp, fontFamily = FontFamily.Monospace) }
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Terminal Output Screen
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(Color(0xFF070A10))
                .padding(12.dp)
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize()
            ) {
                items(lines) { line ->
                    Text(
                        text = line.text,
                        color = if (line.isCommand) CyberCyan else TextPrimaryDark,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        fontWeight = if (line.isCommand) FontWeight.Bold else FontWeight.Normal,
                        modifier = Modifier.padding(vertical = 1.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Command Input Field
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("cyberkit> ", color = CyberCyan, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
            OutlinedTextField(
                value = inputCommand,
                onValueChange = { inputCommand = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                keyboardActions = KeyboardActions(onSend = {
                    val c = inputCommand
                    inputCommand = ""
                    runCommand(c)
                }),
                placeholder = { Text("enter command...", fontSize = 12.sp, fontFamily = FontFamily.Monospace) },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = Color(0xFF1E293B)
                )
            )
            Spacer(modifier = Modifier.width(6.dp))
            IconButton(
                onClick = {
                    val c = inputCommand
                    inputCommand = ""
                    runCommand(c)
                }
            ) {
                Icon(Icons.Default.Send, contentDescription = "Execute", tint = CyberCyan)
            }
        }
    }
}
