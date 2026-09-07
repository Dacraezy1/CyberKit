package com.cyberkit.app.core.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = CyberCyan,
    onPrimary = Color.Black,
    primaryContainer = CyberCardDark,
    onPrimaryContainer = CyberCyan,
    secondary = CyberGreen,
    onSecondary = Color.Black,
    secondaryContainer = CyberSurfaceDark,
    onSecondaryContainer = CyberGreen,
    tertiary = CyberAmber,
    background = CyberBgDark,
    onBackground = TextPrimaryDark,
    surface = CyberSurfaceDark,
    onSurface = TextPrimaryDark,
    surfaceVariant = CyberCardDark,
    onSurfaceVariant = TextSecondaryDark,
    outline = CyberCardBorder,
    error = CyberRed,
    onError = Color.White
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF0284C7),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE0F2FE),
    onPrimaryContainer = Color(0xFF0369A1),
    secondary = Color(0xFF059669),
    onSecondary = Color.White,
    background = CyberBgLight,
    onBackground = TextPrimaryLight,
    surface = CyberSurfaceLight,
    onSurface = TextPrimaryLight,
    surfaceVariant = CyberCardLight,
    onSurfaceVariant = TextSecondaryLight,
    outline = CyberCardBorderLight,
    error = Color(0xFFDC2626),
    onError = Color.White
)

@Composable
fun CyberKitTheme(
    darkTheme: Boolean = true, // Default to dark for cybersecurity aesthetic
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = MaterialTheme.typography,
        content = content
    )
}
