-----

# 🛡️ NIDS Dashboard: Real-Time Network Intrusion Detection System

##  Overview

This project uses a **hybrid architecture** that integrates a **high-performance C++ packet sniffing sensor** with a **modern Node.js backend** and a **live-updating web dashboard** for real-time threat monitoring.
-----
<img src="https://github.com/user-attachments/assets/35be7853-1e48-40d2-9da8-81d3c59394b8" 
     width="850">

-----

| Layer | Technologies |
| :--- | :--- |
| **Sensor** | **C++17**, pcap (Npcap SDK), Winsock2 |
| **Backend** | Node.js, Express.js, **better-sqlite3** |
| **Frontend** | HTML5, CSS3 (Dark Mode), JavaScript (ES6+) |

-----

## ✨ Key Features and Stability ⭐️

### 🧠 High-Performance C++ Sensor (Optimized)

The sensor is now optimized for stability and reliability under network load.

  * **Live Capture:** Captures and analyzes live network traffic using **pcap**.
  * **Packet Parsing:** Extracts Source/Destination IPs, Protocols, and Ports.
  * **Performance Fixes (Critical):** Utilizes **persistent logging streams** and **explicit Winsock initialization** to prevent disk I/O bottlenecks and runtime failures.
  * **Packet Filtering (New):** Applies a **BPF filter** (IP, TCP, ICMP only) at the kernel level to minimize data transfer overhead.

### ⚖️ Smart Detection Engine

The rule logic has been structurally corrected to ensure comprehensive threat coverage.

| Threat Type | Logic Status | Severity |
| :--- | :--- | :--- |
| 🏓 **ICMP Scan** | **Functional** (Threshold \> 3 pings/5s) | Medium |
| 🔒 **Sensitive Ports** | **Functional** (SSH 22, RDP 3389) | High |
| 🚧 **TCP SYN Scans** | **Fixed & Functional.** Detection runs **before** whitelisting to correctly catch scans targeting ports 80/443. | Critical |
| 🌐 **Whitelisting** | Ignores *non-scan* web traffic (80/443) to reduce noise. | — |

### 🧩 Full-Stack Architecture

  * **Backend (Node.js/Express):** Provides a REST API, manages database connections, and uses **stream buffering** to reliably parse real-time JSON alerts from the C++ sensor.
  * **Database (SQLite):** Uses **WAL mode** for high concurrency, storing all structured alerts and logs.
  * **Frontend (HTML/CSS/JS):** Displays a dark-mode dashboard with **auto-refreshing** alerts and triage actions (Acknowledge, Export).

-----

## 🏗️ Data Architecture & Pipeline

The project relies on clean Inter-Process Communication (IPC) for stability:

```text
[ C++ Sensor: nids_sensor.exe ] ↔︎ [ Node.js Backend: child_process ] ↔︎ [ SQLite DB: alerts.db ] ↔︎ [ Web Frontend ]
```

### Key Communications

  * **Sensor Output:** Sends structured JSON alerts via **stdout**.
  * **Backend Control:** Node.js **launches and controls** the C++ sensor process, setting the correct **Device ID** via command-line arguments.
  * **Persistence:** The `ingestAlert()` function handles real-time conversion of raw JSON into a persistent database entry.

-----

## ⚙️ Prerequisites and Setup

Before setup, ensure the following are installed on your **Windows** system:

1.  **Node.js** (v22.x or later)
2.  **Npcap:** Install with the option: *"Install Npcap in WinPcap API-compatible Mode"*.
3.  **Npcap SDK:** Download and unzip (e.g., to `C:\npcap-sdk`).
4.  **C++ Compiler:** `g++` from **MinGW** (or equivalent).

### 1️⃣ Clone the Repository & Configure Path

```bash
git clone https://github.com/ishansaxena012/nids.git
cd nids
```

Edit the Npcap SDK path inside **`scripts/build.bat`**:

```bat
set SDK_PATH=C:\npcap-sdk
```

### 2️⃣ Build and Install Dependencies

```bash
scripts/build.bat
```

### 3️⃣ Start the Platform

The Node.js backend handles starting the C++ sensor and serving the frontend.

```bash
scripts/start.bat
```

  * Backend API runs on **`http://localhost:3000`**
  * Frontend Dashboard runs on **`http://localhost:3001`**

-----

## ▶️ Testing & Verification

1.  **View the Dashboard:** Open your browser and visit the Frontend link.

2.  **Generate Alerts (IPv4 is required\!):** To verify detection logic, run a test that forces IPv4 ICMP traffic:

    ```bash
    ping -4 -n 10 google.com
    ```

    *You should see **"High ICMP traffic detected"** alerts appear on the dashboard.*

-----

## 🧽 Utility Scripts

| Script | Purpose |
| :--- | :--- |
| **`scripts/start.bat`** | Starts backend and frontend servers. |
| **`scripts/build.bat`** | Compiles C++ sensor and installs Node.js dependencies. |
| **`scripts/clear_alerts.bat`** | Clears database tables (`alerts`, `audit_logs`, `notification_queue`) and log files. |

-----

## Author

**Ishan Saxena**
📭 *[06ishansaxena@gmail.com](mailto:06ishansaxena@gmail.com)*

📝 *[linkedin](https://www.linkedin.com/in/ishan-saxena-62781428b/)*

