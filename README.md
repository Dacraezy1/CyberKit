# CyberKit 🛡️
> **Authorized Cybersecurity Assessment and Penetration-Testing Toolkit for Android**

[![CyberKit CI & Build](https://github.com/Dacraezy1/CyberKit/actions/workflows/android.yml/badge.svg)](https://github.com/Dacraezy1/CyberKit/actions/workflows/android.yml)
[![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B%20(API%2026%2B)-blue.svg)](https://developer.android.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/Language-Kotlin%201.9.23-purple.svg)](https://kotlinlang.org)
[![UI](https://img.shields.io/badge/UI-Jetpack%20Compose%20%7C%20Material%203-cyan.svg)](https://developer.android.com/jetpack/compose)

**CyberKit** transforms your Android device into a mobile cybersecurity workstation for authorized security assessments, reconnaissance, auditing, and defensive research. Designed for security professionals, researchers, students, and administrators evaluating systems, networks, applications, and devices they own or have explicit permission to assess.

---

## ⚡ Key Highlights

* **100% Local & Privacy-First:** No telemetry, no third-party analytics, no advertising SDKs, and zero cloud uploads. All analysis runs completely on-device.
* **Non-Root Architecture:** Utilizes legitimate Android APIs, standard Java/Kotlin networking primitives, and graceful fallbacks when system sandbox boundaries apply.
* **Real Diagnostic Engine:** Eliminates mock/dummy screens in favor of real TCP socket connections, live DNS queries, TLS handshakes, binary XML parsing, Shannon entropy math, and secret regex matching.
* **Unified Finding Model:** Standardized scoring and findings engine (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) providing evidence, confidence ratings, and actionable remediation steps.
* **Comprehensive Multi-Format Reporting:** Export assessments in JSON, CSV, TXT, or executive-ready HTML.

---

## 🧰 Modular Workstation Capabilities

### 1. Authorized Network Reconnaissance & Diagnostics
* **Network Interfaces:** Real-time enumeration of network adapters, IPv4/IPv6 addresses, MTU, loopback, and routing details.
* **CIDR & Subnet Calculator:** IPv4/IPv6 boundary calculation, network/broadcast addresses, subnet/wildcard masks, and host capacity.
* **Host Discovery:** Subnet discovery combining `InetAddress.isReachable` and multi-port TCP handshakes/RST detection for unprivileged environments.
* **Wi-Fi Security Analyzer:** Frequency band (2.4 GHz, 5 GHz, 6 GHz), channel calculation, RSSI signal gauge, gateway diagnostics, and defensive guidance.
* **DNS Toolkit:** Live query resolution for `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, DNSSEC Authenticated Data (`AD`) verification, and reverse PTR lookups.

### 2. TCP Port Scanner & Service Detection
* **High-Performance Scanning:** Configurable concurrency semaphores, timeout controls, and coroutine cancellation.
* **Presets:** Quick Top 20, Web Services, System Administration, Databases, and custom port ranges (`1-1024`).
* **Safe Service Fingerprinting:** Safe banner grabbing and protocol negotiation for HTTP, TLS, SSH, FTP, and SMTP without sending exploit payloads.
* **State Classification:** Differentiates between `OPEN` (SYN-ACK), `CLOSED` (RST), and `FILTERED` (firewall drop / timeout).

### 3. Web & TLS Security Assessment
* **URL Checker:** Inspects syntax, scheme, unusual ports, and homograph / Punycode anomalies.
* **HTTP Security Headers:** Audits HSTS (`Strict-Transport-Security`), Content Security Policy (`CSP`), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and cookie security flags (`Secure`, `HttpOnly`, `SameSite`).
* **TLS Certificate Analyzer:** Certificate chain evaluation, Subject, Issuer, Subject Alternative Names (SAN), signature algorithm verification, public key length (RSA/EC), and system CA validation.
* **Non-Destructive Web Audits:** Verifies HTTP-to-HTTPS redirect enforcement and CORS wildcard configurations.

### 4. APK Security Analyzer
* **Local AXML Decoding:** Custom in-memory Android Binary XML (AXML) decoder extracting `AndroidManifest.xml` without external binaries.
* **Component Surface Analysis:** Detects exported Activities, Services, Broadcast Receivers, and Content Providers lacking custom permission gates.
* **Manifest Flags Audit:** Flags `android:debuggable="true"`, `android:allowBackup="true"`, and `android:usesCleartextTraffic="true"`.
* **Dangerous Permissions Audit:** Identifies sensitive device capabilities requested by the application.
* **DEX & Bytecode Heuristics:** Scans for embedded plaintext HTTP endpoints, API tokens, and native `.so` library architectures.
* **Cryptographic Hashes & Signatures:** Computes MD5, SHA-1, SHA-256, SHA-512, extracts signing certificate fingerprints, and supports hash comparison.

### 5. File Security, Entropy & Secret Scanner
* **Shannon Entropy Engine:** Computes Shannon entropy (0.0 to 8.0 bits/byte) to identify packed, compressed, or encrypted files.
* **Format & Magic Bytes:** Identifies ELF, PE/MZ, DEX, and shell script headers.
* **Archive Security Inspector:** Inspects ZIP, JAR, and APK archives with built-in detection for Zip Slip (path traversal `../`) vulnerabilities and embedded executables.
* **Secret Scanner:** Multi-pattern regex and high-entropy detection for AWS Access Keys, GitHub PATs, Google API Keys, Slack tokens, Stripe keys, and Private Key markers with line-by-line evidence and masked previews.

### 6. Android Device Security & App Audit
* **Device Security Posture:** Audits screen lock configuration (`KeyguardManager`), hardware/storage encryption status, monthly security patch date & age, developer options, and USB debugging (ADB) status.
* **Installed Applications Analyzer:** Audits third-party applications for outdated `targetSdkVersion` (< 31) and excessive dangerous permissions.

### 7. Cryptography & CVSS Toolkit
* **Hashes & HMAC:** MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA512.
* **Encoders & Decoders:** Base64 (RFC 4648), Hexadecimal, URL encoding/decoding, Binary bitstream representation, and UUID v4 generator.
* **Password Security Analyzer:** 100% memory-only entropy calculation, pattern repetition checks, sequential key run detection, common leaked password dictionary matching, and crack-time estimation.
* **CVSS v3.1 Risk Calculator:** Full FIRST CVSS v3.1 implementation computing Base Scores, Exploitability/Impact subscores, vector strings, and qualitative severity ratings.

### 8. Smart Audit Pipeline
One-click unified assessment engine combining tools into consolidated reports:
* 📱 **My Device:** OS security posture + installed application permissions.
* 📶 **My Wi-Fi:** Wireless encryption, signal strength, gateway latency, and DNS validation.
* 🌐 **My Local Network:** Subnet discovery + host enumeration + port diagnostics.
* 🌍 **My Website:** URL audit + TLS analysis + HTTP security headers.
* 📦 **My APK:** Manifest deconstruction + exported component review + cryptographic verification.
* 📁 **My Files:** Format inspection + entropy evaluation + secret scanning.

### 9. Interactive Cybersecurity Labs
Safe, simulated educational modules covering:
* TCP 3-Way Handshake & Port States (Open vs Closed vs Filtered)
* IPv4 Subnetting & CIDR Address Boundaries
* HTTP Security Headers & Cross-Site Defenses
* TLS Certificate Validation & Man-In-The-Middle Prevention
* Android Component Export Risks & Intent Filters
* Cryptographic Hashing, Salts & Key Stretching

### 10. CyberKit Interactive Shell
Monospace terminal console providing unified command-line control over implemented CyberKit capabilities:
```bash
cyberkit> help
cyberkit> netinfo
cyberkit> subnet 192.168.1.0/24
cyberkit> discover 192.168.1.0/24
cyberkit> scan 192.168.1.1 22,80,443
cyberkit> dns cloudflare.com
cyberkit> tls google.com 443
cyberkit> url https://example.com
cyberkit> hash sha256 CyberKitSecurity
cyberkit> cvss CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
cyberkit> password MySecurePassphrase#2026
```

---

## 🏗️ Architecture & Technology Stack

```
com.cyberkit.app/
├── core/
│   ├── model/       # Standardized Finding, FindingSeverity, AssessmentSummary
│   ├── database/    # Room Database (ScanRecordEntity, ScanDao, CyberKitDatabase)
│   └── theme/       # Dark/Light cybersecurity theme, colors & typography
├── network/         # PortScanner, HostDiscovery, ServiceDetection, DnsToolkit, WifiAnalyzer
├── web/             # UrlAnalyzer, TlsAnalyzer, WebSecurityScanner
├── apk/             # AxmlDecoder, ApkAnalyzer, SignatureVerifier
├── files/           # FileSecurityAnalyzer, EntropyCalculator, SecretScanner, ArchiveInspector
├── device/          # DeviceAuditor, InstalledAppAnalyzer
├── crypto/          # CryptoToolkit, PasswordAnalyzer
├── cvss/            # CvssCalculator (CVSS v3.1 specification)
├── smartaudit/      # SmartAuditCoordinator (composite multi-tool orchestrator)
├── reports/         # ReportGenerator (JSON, CSV, TXT, HTML)
├── labs/            # SecurityLabRepository (educational challenge engine)
├── terminal/        # CyberKitTerminalEngine (interactive workstation shell)
└── ui/              # Jetpack Compose UI screens, navigation & reusable components
```

---

## 🚀 Building & CI/CD Pipeline

The project is configured with automated GitHub Actions in `.github/workflows/android.yml`.

### Automated Pipeline Workflow:
1. Clones repository.
2. Sets up Eclipse Temurin JDK 17.
3. Sets up Android SDK 34 and build tools.
4. Executes unit tests (`./gradlew testReleaseUnitTest`).
5. Assembles signed Release APK (`CyberKit.apk`) and Debug APK (`CyberKit-debug.apk`).
6. Publishes artifacts directly to GitHub Actions build run.

No local Android Studio or SDK installation is required on the developer's workstation.

---

## ⚖️ Legal & Ethical Notice

CyberKit is developed exclusively for authorized security diagnostics, system administration, network testing, and defensive education. Scanning networks, websites, or applications without prior explicit authorization from the owner is illegal and unethical. The developer assumes no liability for unauthorized or misuse of this software.
