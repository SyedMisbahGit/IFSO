# run_test.py
import os
import time

def send(description, cmd):
    print(f"\n🚀 {description}")
    os.system(cmd)
    time.sleep(1)

print("\n🎯 Sending test payloads for all severities...\n")

# High severity
send("Command Injection (powershell)",       "curl --data 'cmd=powershell' http://127.0.0.1:9999")
send("Remote Code Exec (eval)",              "curl --data 'cmd=eval' http://127.0.0.1:9999")
send("Wiper Command (rm -rf)",               "curl --data 'cmd=rm -rf' http://127.0.0.1:9999")
send("Malware Domain (malware.example)",     "curl --data 'host=malware.example' http://127.0.0.1:9999")

# Medium severity
send("XSS (script)",                         "curl --data 'input=<script>alert(1)</script>' http://127.0.0.1:9999")
send("Recon Domain (suspicious.com)",        "curl --data 'site=suspicious.com' http://127.0.0.1:9999")
send("Recon Tool (wget)",                    "curl --data 'cmd=wget http://example.com/file' http://127.0.0.1:9999")

# Low severity
send("Test Payload (example.com)",           "curl --data 'domain=example.com' http://127.0.0.1:9999")
# --- NEW TEST FOR FACEBOOK.COM ---
send("Monitored Domain (facebook.com)",      "curl --data 'site=facebook.com' http://127.0.0.1:9999")


print("\n✅ Done. Check alerts.log and packet_labels.csv.")