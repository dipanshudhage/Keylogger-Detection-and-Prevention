# 🛡️ Keylogger Detection & Prevention Tool

## 📌 Project Overview
This project is a defensive cybersecurity tool designed to detect and prevent
keylogger-like threats on Windows systems using Python.

The tool focuses on **monitoring suspicious processes**, **risk-based detection**,
and **real-time alerts**, without capturing keystrokes.

---

## 🎯 Problem Statement
Keyloggers are malicious programs that secretly record keyboard inputs
to steal sensitive data. Most users are unaware of such threats.
This project aims to **detect and warn users** about potential keylogger activity.

---

## 🚀 Features
- Real-time process monitoring
- Risk-based detection engine
- Startup persistence scan
- GUI-based alerts
- Automatic log saving (TXT & JSON)
- Ethical & privacy-safe (no keystroke logging)

---

## 🛠️ Technology Used
- Python
- Windows OS
- psutil
- tkinter
- JSON logging

---

## ▶️ How to Run
```bash
pip install -r requirements.txt
python keylogger_detector.py
