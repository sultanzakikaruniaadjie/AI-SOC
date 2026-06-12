# agent.py
# Jalankan: python agent.py
# Agent ini baca log Windows Event / file log, lalu kirim ke AI-SOC backend
# Letakkan di root folder AI-SOC/

import time
import random
import requests
import datetime

# ── Konfigurasi ───────────────────────────────────────────────────────────────
SOC_URL  = "http://localhost:5000/api/attack"
INTERVAL = 5   # detik antar pengecekan

# ── Data simulasi (untuk demo hackathon tanpa server beneran) ─────────────────
SIMULATED_ATTACKS = [
    {"attack": "SQL Injection",   "ip": "203.45.67.89",  "country": "China",       "risk": "Critical"},
    {"attack": "Brute Force",     "ip": "185.24.55.12",  "country": "Russia",      "risk": "High"},
    {"attack": "XSS Attack",      "ip": "91.108.4.200",  "country": "Netherlands", "risk": "High"},
    {"attack": "Port Scanning",   "ip": "45.91.120.10",  "country": "Germany",     "risk": "Medium"},
    {"attack": "Path Traversal",  "ip": "103.21.244.0",  "country": "Vietnam",     "risk": "Critical"},
    {"attack": "Brute Force",     "ip": "198.51.100.42", "country": "Brazil",      "risk": "High"},
    {"attack": "SQL Injection",   "ip": "192.0.2.100",   "country": "India",       "risk": "Critical"},
]

def send_attack(data):
    """Kirim data serangan ke AI-SOC backend"""
    try:
        r = requests.post(SOC_URL, json=data, timeout=5)
        if r.status_code == 201:
            resp = r.json()
            print(f"  ✅ Tersimpan → ID:{resp.get('id')} | {data['attack']} dari {data['ip']} [{data['risk']}]")
        else:
            print(f"  ⚠️  Gagal simpan ({r.status_code}): {r.text[:80]}")
    except requests.exceptions.ConnectionError:
        print("  ❌ Tidak bisa konek ke server. Pastikan server.js sedang berjalan di port 5000.")
    except Exception as e:
        print(f"  ❌ Error: {e}")

def read_windows_event_log():
    """
    Baca Windows Security Event Log (butuh library pywin32).
    Kalau tidak tersedia, return None dan pakai simulasi.
    """
    try:
        import win32evtlog
        import win32con

        server   = "localhost"
        log_type = "Security"
        hand     = win32evtlog.OpenEventLog(server, log_type)
        flags    = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
        events   = win32evtlog.ReadEventLog(hand, flags, 0)

        found = []
        for event in events[:10]:  # ambil 10 event terbaru
            event_id = event.EventID & 0xFFFF
            # Event ID 4625 = failed logon (brute force)
            if event_id == 4625:
                found.append({
                    "attack":  "Brute Force",
                    "ip":      "0.0.0.0",
                    "country": "Unknown",
                    "risk":    "High"
                })
            # Event ID 4719 = system audit policy changed
            elif event_id == 4719:
                found.append({
                    "attack":  "Policy Tampering",
                    "ip":      "0.0.0.0",
                    "country": "Unknown",
                    "risk":    "Critical"
                })
        win32evtlog.CloseEventLog(hand)
        return found if found else None

    except ImportError:
        return None  # pywin32 tidak ada, pakai simulasi
    except Exception:
        return None

def simulate_attack():
    """
    Mode simulasi: pilih serangan random untuk demo hackathon.
    Probability 40% ada serangan tiap interval, 60% aman.
    """
    if random.random() < 0.4:
        return random.choice(SIMULATED_ATTACKS)
    return None

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  🛡️  AI-SOC Agent — Log Monitor")
    print("=" * 55)
    print(f"  Target  : {SOC_URL}")
    print(f"  Interval: setiap {INTERVAL} detik")
    print(f"  Mode    : Windows Event Log (fallback → simulasi)")
    print("  Ctrl+C untuk berhenti")
    print("-" * 55)

    cycle = 0
    while True:
        cycle += 1
        now = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n[{now}] Siklus #{cycle} — mengecek log...")

        # Coba baca log Windows asli dulu
        events = read_windows_event_log()

        if events:
            print(f"  📋 {len(events)} event dari Windows Security Log")
            for ev in events:
                send_attack(ev)
        else:
            # Fallback ke simulasi
            attack = simulate_attack()
            if attack:
                print(f"  🚨 Simulasi serangan terdeteksi!")
                send_attack(attack)
            else:
                print("  ✓  Tidak ada ancaman terdeteksi")

        time.sleep(INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Agent dihentikan.")