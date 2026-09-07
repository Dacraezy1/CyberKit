package com.cyberkit.app.labs

data class SecurityLab(
    val id: String,
    val title: String,
    val category: String,
    val difficulty: String,
    val description: String,
    val learningObjectives: List<String>,
    val conceptSummary: String,
    val challengePrompt: String,
    val options: List<String>,
    val correctIndex: Int,
    val explanation: String,
    val defensiveTakeaway: String
)

object SecurityLabRepository {

    val LABS = listOf(
        SecurityLab(
            id = "lab_ports",
            title = "TCP Port Scanning States: Open vs Closed vs Filtered",
            category = "Network",
            difficulty = "Beginner",
            description = "Learn how TCP three-way handshakes reflect port states and firewall behaviors.",
            learningObjectives = listOf(
                "Differentiate between SYN-ACK (Open), RST (Closed), and Timeout (Filtered)",
                "Understand why firewalls drop packets silently"
            ),
            conceptSummary = "During a TCP connect scan, the client transmits a SYN packet. If the listening application is active, it replies with SYN-ACK (OPEN). If no service listens on the port, the operating system kernel immediately returns RST (CLOSED). If an intermediate stateful firewall or packet filter drops the SYN packet without responding, the scanner eventually times out (FILTERED).",
            challengePrompt = "A scanner sends a TCP SYN packet to port 443. After 3000ms, no packet has been returned and the socket times out. What is the most accurate diagnostic conclusion?",
            options = listOf(
                "The port is CLOSED because the server sent a RST packet",
                "The port is FILTERED by a firewall or network drop rule",
                "The port is OPEN and waiting for application TLS data",
                "The host does not exist on the network"
            ),
            correctIndex = 1,
            explanation = "When a port fails to respond within the socket timeout period, the probe has likely been silently dropped by a firewall or routing rule, indicating a FILTERED state.",
            defensiveTakeaway = "Firewalls should drop unsolicited inbound connection attempts rather than rejecting with RST to slow down automated reconnaissance."
        ),
        SecurityLab(
            id = "lab_subnet",
            title = "IPv4 Subnetting & CIDR Boundary Calculations",
            category = "Network",
            difficulty = "Beginner",
            description = "Master IP address ranges, broadcast addresses, and usable host counts in CIDR prefixes.",
            learningObjectives = listOf(
                "Calculate network and broadcast boundaries for any CIDR mask",
                "Identify first and last assignable host addresses"
            ),
            conceptSummary = "In an IPv4 subnet designated /26, 26 bits are dedicated to the network prefix, leaving 32 - 26 = 6 bits for host addressing. Total addresses = 2^6 = 64. The first address is reserved as the Network identifier, and the final address is reserved as the Broadcast address. Therefore, usable hosts = 64 - 2 = 62.",
            challengePrompt = "For the network block 192.168.10.64/26, what is the broadcast address and how many usable hosts exist?",
            options = listOf(
                "Broadcast: 192.168.10.127 | Usable hosts: 62",
                "Broadcast: 192.168.10.255 | Usable hosts: 64",
                "Broadcast: 192.168.10.128 | Usable hosts: 62",
                "Broadcast: 192.168.10.63  | Usable hosts: 30"
            ),
            correctIndex = 0,
            explanation = "With a block size of 64, the network runs from .64 to .127. 192.168.10.127 is the broadcast address, with usable hosts from .65 to .126 (total 62).",
            defensiveTakeaway = "Proper network microsegmentation using restrictive CIDR prefixes limits lateral movement during an internal compromise."
        ),
        SecurityLab(
            id = "lab_headers",
            title = "HTTP Security Headers & Modern Browser Protections",
            category = "Web",
            difficulty = "Intermediate",
            description = "Explore how HSTS, CSP, and X-Frame-Options prevent client-side web attacks.",
            learningObjectives = listOf(
                "Understand how HSTS defends against SSL stripping",
                "Analyze Content Security Policy directives to mitigate XSS",
                "Prevent Clickjacking via framing controls"
            ),
            conceptSummary = "HTTP Strict Transport Security (HSTS) informs user agents that all future requests to the domain must strictly use HTTPS, refusing cleartext HTTP connections even if the user types 'http://'. Content Security Policy (CSP) restricts what domains scripts, styles, and media can load from.",
            challengePrompt = "Which HTTP response header explicitly instructs modern browsers to prevent the webpage from being rendered inside an <iframe> to stop Clickjacking?",
            options = listOf(
                "Strict-Transport-Security: max-age=31536000",
                "X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
                "X-Content-Type-Options: nosniff",
                "Access-Control-Allow-Origin: *"
            ),
            correctIndex = 1,
            explanation = "X-Frame-Options: DENY or CSP frame-ancestors directives tell the browser to refuse embedding the document inside frames or iframes, mitigating clickjacking.",
            defensiveTakeaway = "Always configure defensive HTTP headers at the edge reverse proxy (Cloudflare, Nginx, or Envoy)."
        ),
        SecurityLab(
            id = "lab_tls",
            title = "TLS Certificate Chains & Man-in-the-Middle Defense",
            category = "Web",
            difficulty = "Intermediate",
            description = "Examine X.509 certificate validation, Subject Alternative Names (SAN), and Root CA trusts.",
            learningObjectives = listOf(
                "Trace certificate paths from Leaf to Intermediate to Root CA",
                "Identify risks of self-signed certificates in untrusted networks"
            ),
            conceptSummary = "A TLS client validates that: (1) Current date is between NotBefore and NotAfter; (2) The requested hostname matches the Subject Alternative Name (SAN) extension; (3) The issuer signature chains to a trusted Root CA embedded in the device trust store.",
            challengePrompt = "Why does a self-signed certificate generate a critical warning in client browsers even if it uses strong 4096-bit RSA keys?",
            options = listOf(
                "Because self-signed certificates cannot encrypt data over the wire",
                "Because the client cannot cryptographically establish the server's authentic identity through a trusted third-party Root CA",
                "Because RSA 4096-bit keys are unsupported by mobile devices",
                "Because self-signed certificates lack expiration dates"
            ),
            correctIndex = 1,
            explanation = "While a self-signed certificate can establish an encrypted channel, without a trusted CA signature, an attacker on the network can substitute their own certificate without detection (MITM).",
            defensiveTakeaway = "Deploy automated certificate issuance (ACME) with public CAs and implement Certificate Transparency monitoring."
        ),
        SecurityLab(
            id = "lab_apk",
            title = "Android APK Components & Exported Surface Vulnerabilities",
            category = "APK",
            difficulty = "Advanced",
            description = "Inspect AndroidManifest.xml component export rules, intent filters, and permission boundaries.",
            learningObjectives = listOf(
                "Understand the implications of android:exported='true'",
                "Analyze implicit vs explicit intent handling"
            ),
            conceptSummary = "In Android, Activities, Services, and BroadcastReceivers with an <intent-filter> default to exported='true' on older Android versions unless explicitly set to false. Exported components can be triggered by ANY application on the device, potentially allowing unauthorized task execution or data leakage if not guarded by custom permissions.",
            challengePrompt = "A developer creates a database sync Service with android:exported='true' and no android:permission attribute. What is the security risk?",
            options = listOf(
                "The app cannot be compiled on Android 14",
                "Any arbitrary malware application on the device can start or bind to this service and manipulate synchronization",
                "The service can only be reached over Wi-Fi",
                "Android OS will automatically revoke the application's internet permission"
            ),
            correctIndex = 1,
            explanation = "Exported components lacking custom permission gates can be invoked by any installed third-party application via standard Android IPC (Intents).",
            defensiveTakeaway = "Always set android:exported='false' for internal application components unless external integration is strictly necessary."
        ),
        SecurityLab(
            id = "lab_hash",
            title = "Cryptographic Hashing, Salts & Collision Attacks",
            category = "Crypto",
            difficulty = "Beginner",
            description = "Explore deterministic one-way functions, rainbow table vulnerabilities, and password hashing.",
            learningObjectives = listOf(
                "Understand why MD5 and SHA-1 are broken for digital signatures",
                "Understand the role of cryptographic salt and key-stretching functions (PBKDF2, Argon2, bcrypt)"
            ),
            conceptSummary = "Cryptographic hash functions must be preimage resistant, second-preimage resistant, and collision resistant. MD5 and SHA-1 have known collision generation techniques. Furthermore, fast hashes (like SHA-256) are inappropriate for passwords without key-stretching algorithms (Argon2, bcrypt) because GPUs can compute billions of guesses per second.",
            challengePrompt = "Why should salted Argon2 or bcrypt be used for password storage instead of single-iteration SHA-256?",
            options = listOf(
                "Because SHA-256 is vulnerable to length extension attacks only",
                "Because Argon2 and bcrypt are deliberately computationally and memory intensive, dramatically increasing the cost of offline brute-force attacks",
                "Because SHA-256 produces variable length outputs",
                "Because bcrypt produces unencrypted plain text"
            ),
            correctIndex = 1,
            explanation = "Modern password hashing functions use memory-hardness and configurable work factors to make GPU and ASIC parallel password cracking computationally and economically unfeasible.",
            defensiveTakeaway = "Never hash passwords with raw fast algorithms (MD5, SHA-1, SHA-256); always use Argon2id or bcrypt with appropriate work factors."
        )
    )
}
