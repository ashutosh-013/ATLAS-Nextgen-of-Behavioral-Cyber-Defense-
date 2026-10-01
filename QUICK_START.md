# 🛡️ ATLAS — 1-Click Turnkey Installation & Quick Start Guide

Welcome to the **ATLAS Behavioral Cyber-Intelligence Platform**. This guide explains how to install and run ATLAS on any Windows PC in **1 click**.

---

## ⚡ Option 1: Standalone Windows Setup Installer (.exe) — No Python Needed (Recommended)

Anyone can run ATLAS without installing Python, Git, or dependencies:

1. **Download `ATLAS_v2.5_Enterprise_Setup.exe`** from the [GitHub Releases](https://github.com/ashutosh-013/ATLAS-Nextgen-of-Behavioral-Cyber-Defense-/releases).
2. **Double-click `ATLAS_v2.5_Enterprise_Setup.exe`**.
   - The modern Windows Setup Wizard will install ATLAS into your Program Files.
   - It creates an **ATLAS Cyber Defense** Desktop icon and Start Menu entry.
   - Automatically provisions local database storage in `%LOCALAPPDATA%\ATLAS\` to guarantee clean write permissions.
3. **Launch ATLAS**:
   - Double-click the desktop icon to launch the native cyber defense platform.

---

## 🛠️ Option 2: 1-Click Automated Batch Setup (From Source)

If you have cloned the repository with source code:

1. **Double-click `install_atlas.bat`**.
   - It will automatically request Administrator permissions (UAC popup) to configure the local Windows Firewall and ETW sensors.
   - It will create an isolated virtual environment (`.venv`), install all required libraries from `requirements.txt`, provision runtime directories, initialize the database, seed the knowledge base, and perform a 7-layer diagnostic pre-flight check.
   - It will place an **"ATLAS Security Platform"** shortcut on your Desktop!
2. **Double-click the Desktop shortcut (or run `start_atlas.bat`)** to start ATLAS.
   - Your default browser will automatically open to `http://localhost:5000/`.

---

## 🚀 Option 2: Command Line Setup

If you prefer using PowerShell or CMD:

```powershell
# 1. Navigate to the project directory
cd E:\BADNA

# 2. Run the environment setup & diagnostic engine
python setup_environment.py

# 3. Launch ATLAS
.\start_atlas.bat
```

---

## 📋 What the Installer Automatically Configures

| Component | Automated Action |
| :--- | :--- |
| **Administrator Privileges** | Requests UAC elevation for real-time Windows Defender Firewall rule manipulation and process containment. |
| **Python Environment** | Creates isolated `.venv` and installs `flask`, `psutil`, `torch`, `scikit-learn`, `networkx`, `requests`, `pyyaml`, `cryptography`. |
| **Directories** | Generates `data/`, `logs/`, `config/`, `intelligence/feeds/`, `behavior/canaries/`, `backups/`, `scratch/`. |
| **Database & Knowledge Base** | Seeds SQLite schema, MITRE ATT&CK techniques, CISA KEV catalog (1,240+ CVEs), and baseline configuration. |
| **7-Layer Pre-Flight Diagnostics** | Executes a full diagnostic scan across all 7 layers (Health, Endpoint, Network, Behavioral d-BEF, Threat Intel, Ransomware, AI Cognitive Analysis). |
| **Desktop Shortcut** | Creates `ATLAS Security Platform.lnk` on your Windows Desktop for quick 1-click launching. |

---

## 🛑 How to Stop ATLAS
When you are done, press any key in the `start_atlas.bat` console window. It will cleanly terminate background workers, agents, and web servers.
