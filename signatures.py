# signatures.py
import re

attack_signatures = {
    r'\bpowershell\b': ('Command Injection', 'High', 'Inspect scripts and disable PowerShell if not needed.'),
    r'\beval\s*\(': ('Remote Code Execution (PHP)', 'High', 'Audit PHP code. Avoid using eval with user input.'),
    r'\bexec\s*\(': ('Remote Code Execution', 'High', 'Limit system command execution rights.'),
    r'base64\s*(decode|decode64)?': ('Obfuscation', 'High', 'Check for hidden scripts or commands.'),
    r'/bin/sh': ('Command Injection', 'High', 'Check for unauthorized shell access.'),
    r'<script.*?>': ('Cross Site Scripting (XSS)', 'Medium', 'Sanitize user input in web forms.'),
    r'drop\s+table': ('SQL Injection', 'High', 'Use prepared statements in SQL queries.'),
    r'--': ('SQL Injection', 'High', 'Use parameterized queries.'),
    r'\bwget\b': ('File Download (Recon)', 'Medium', 'Audit outbound traffic. Block suspicious domains.'),
    r'\bcurl\b': ('File Download / Reconnaissance', 'Medium', 'Monitor command-line utilities.'),
    r'rm\s+-rf': ('Destruction / Wiper', 'High', 'Implement file deletion restrictions.'),
    r'chmod\s+777': ('Privilege Escalation', 'High', 'Use principle of least privilege.'),
    r'netcat': ('Backdoor / Reverse Shell', 'High', 'Block unnecessary ports and tools.'),
    r'nc\s+-e': ('Reverse Shell Execution', 'High', 'Disable netcat or restrict its use.'),
    r'\.onion': ('Dark Web Access', 'Medium', 'Block Tor traffic.'),
    r'malware\..*': ('DNS Query - Malware Domain', 'High', 'Use DNS sinkholes. Block malicious domains.'),
    r'phishing\..*': ('DNS Query - Phishing', 'High', 'Deploy phishing protection on endpoints.'),
    r'example\.com': ('Test Payload', 'Low', 'No action needed (test payload).'),
    r'suspicious\.com': ('Suspicious Domain', 'Medium', 'Investigate domain reputation.'),
    # --- NEW SIGNATURE FOR FACEBOOK.COM ---
    r'facebook\.com': ('Monitored Domain', 'Low', 'Traffic to Facebook domain detected. Review user activity if unexpected.')
}