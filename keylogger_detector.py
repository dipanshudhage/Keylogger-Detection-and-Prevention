import psutil
import os
import time
import threading
import json
import tkinter as tk
from tkinter import messagebox

# ---------- CONFIG ----------
SCAN_INTERVAL = 5
RISK_THRESHOLD = 60
SUSPICIOUS_KEYWORDS = ["keylog", "hook", "spy", "logger", "keyboard"]

LOG_DIR = "logs"
TXT_LOG_FILE = os.path.join(LOG_DIR, "security_log.txt")
JSON_LOG_FILE = os.path.join(LOG_DIR, "security_log.json")

STARTUP_DIRS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]

os.makedirs(LOG_DIR, exist_ok=True)

# ---------- GLOBALS ----------
running = False
known_pids = set()
json_logs = []

# ---------- RISK ENGINE ----------
def calculate_risk(proc):
    score = 0
    name = (proc.info.get("name") or "").lower()

    for k in SUSPICIOUS_KEYWORDS:
        if k in name:
            score += 40
            break

    try:
        exe = proc.exe().lower()
        if "\\appdata\\" in exe or "\\temp\\" in exe:
            score += 30
    except:
        pass

    return score

def get_startup_entries():
    files = set()
    for d in STARTUP_DIRS:
        if os.path.isdir(d):
            for f in os.listdir(d):
                files.add(f.lower())
    return files

startup_cache = get_startup_entries()

# ---------- LOGGING ----------
def write_txt_log(msg):
    with open(TXT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def write_json_log(entry):
    json_logs.append(entry)
    with open(JSON_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(json_logs, f, indent=4)

def log(msg, level="INFO"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    final_msg = f"{timestamp} [{level}] {msg}"

    log_box.insert(tk.END, final_msg + "\n")
    log_box.see(tk.END)

    write_txt_log(final_msg)
    write_json_log({
        "time": timestamp,
        "level": level,
        "message": msg
    })

# ---------- MONITOR ----------
def scan_processes():
    alerts = []

    for proc in psutil.process_iter(["pid", "name", "username"]):
        try:
            pid = proc.info["pid"]
            if pid in known_pids:
                continue
            known_pids.add(pid)

            risk = calculate_risk(proc)
            if risk >= RISK_THRESHOLD:
                alerts.append((pid, proc.info["name"], risk))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return alerts

def monitor_loop():
    while running:
        threats = scan_processes()
        if threats:
            for pid, name, risk in threats:
                log(f"Threat detected | PID={pid} | Process={name} | Risk={risk}", "ALERT")
            messagebox.showwarning(
                "Threat Alert",
                "⚠️ Potential keylogger-like activity detected.\nCheck logs."
            )
        time.sleep(SCAN_INTERVAL)

# ---------- GUI ----------
root = tk.Tk()
root.title("Advanced Keylogger Detection & Prevention")
root.geometry("900x560")

title = tk.Label(
    root,
    text="🛡️ Advanced Keylogger Detection & Prevention Tool",
    font=("Arial", 14, "bold")
)
title.pack(pady=8)

log_box = tk.Text(root, height=23, width=108)
log_box.pack(padx=10, pady=8)

# ---------- BUTTON ACTIONS ----------
def start_monitor():
    global running
    if not running:
        running = True
        log("Monitoring started")
        threading.Thread(target=monitor_loop, daemon=True).start()

def stop_monitor():
    global running
    running = False
    log("Monitoring stopped")

def scan_startup():
    current = get_startup_entries()
    new_entries = current - startup_cache

    if new_entries:
        for item in new_entries:
            log(f"Suspicious startup entry detected: {item}", "WARNING")
        messagebox.showwarning("Startup Alert", "Suspicious startup items found.")
    else:
        log("No suspicious startup entries found")

def save_logs_info():
    messagebox.showinfo(
        "Logs Saved",
        f"Logs are being saved in real-time:\n\n{TXT_LOG_FILE}\n{JSON_LOG_FILE}"
    )

# ---------- BUTTONS ----------
btn_frame = tk.Frame(root)
btn_frame.pack(pady=6)

tk.Button(btn_frame, text="Start Monitoring", bg="green", fg="white",
          width=18, command=start_monitor).grid(row=0, column=0, padx=5)

tk.Button(btn_frame, text="Stop Monitoring", bg="red", fg="white",
          width=18, command=stop_monitor).grid(row=0, column=1, padx=5)

tk.Button(btn_frame, text="Scan Startup", width=18,
          command=scan_startup).grid(row=0, column=2, padx=5)

tk.Button(btn_frame, text="Save Logs (TXT)", width=18,
          command=save_logs_info).grid(row=0, column=3, padx=5)

tk.Button(btn_frame, text="Save Logs (JSON)", width=18,
          command=save_logs_info).grid(row=0, column=4, padx=5)

tk.Label(
    root,
    text="✔ Defensive tool • ✔ No keystroke capture • ✔ Real-time logging",
    fg="gray"
).pack(pady=4)

root.mainloop()
