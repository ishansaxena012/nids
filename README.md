

## 🚀 Overview

This project uses a **hybrid architecture** that integrates:

- ⚙️ A **high-performance C++ packet sniffing sensor**
- 🌐 A **modern Node.js backend**
- 📊 A **live-updating web dashboard**

The **C++ sensor** performs low-level packet capture and rule-based analysis, while the **Node.js backend** manages alerts, APIs, and database operations — all visualized through a responsive frontend dashboard.
<img width="1890" height="907" alt="image" src="https://github.com/user-attachments/assets/9f48468b-815f-4dea-ae2b-1bae04ce615e" />



---

## ✨ Features

### 🧠 High-Performance C++ Sensor
- Captures **live network traffic** in real-time using **pcap**.
- Parses **Ethernet, IP, and TCP headers** to extract:
  - Source/Destination IPs
  - Protocols
  - Ports

### ⚖️ Smart Rule Engine (C++)
Detects common suspicious activities:
| Threat Type | Description | Severity |
|--------------|--------------|-----------|
| 🏓 ICMP Scan | Detects ICMP (Ping) scans | Medium |
| 🔒 Sensitive Ports | Detects connections to SSH (22) or RDP (3389) | High |
| 🚧 TCP SYN Scans | Detects generic TCP SYN scans on non-standard ports | High |
| 🌐 Whitelisting | Ignores normal web traffic (80/443) to reduce false positives | — |

### 🧩 Full-Stack Architecture
- **Backend (Node.js/Express):**
  - Provides a REST API (`/api/alerts`, `/api/rules`)
  - Manages database and child processes
- **Database (SQLite):**
  - Stores all alerts, rules, and logs
- **Frontend (HTML/CSS/JS):**
  - Displays a **dark-mode dashboard**
  - Auto-refreshes with **real-time data**

### 🔄 Inter-Process Communication
- The Node.js backend **launches** and **controls** the C++ sensor.
- Alerts are sent via **stdout** as JSON.
- Logs and debug messages are sent to **stderr** (to avoid corruption).

### 🧰 Utility Scripts
| Script | Description |
|--------|-------------|
| `scripts/start.bat` | Starts both backend and frontend servers |
| `scripts/build.bat` | Compiles C++ sensor & installs dependencies |
| `scripts/clear_alerts.bat` | Clears database alerts and logs |

---

## 🏗️ Architecture

```text
[ C++ Sensor ]  →  [ Node.js Backend ]  →  [ Web Frontend ]
````

### 🔹 C++ Sensor (`/sensor`)

  * Core engine: `packet_sniffer.cpp`
  * Built into: `nids_sensor.exe`
  * Uses **pcap** to capture network packets
  * Analyzes packets using rule-based logic
  * Sends structured **JSON alerts** to stdout

### 🔹 Node.js Backend (`/backend`)

  * Launches and manages the C++ sensor
  * Listens to stdout for real-time alerts
  * Ingests alerts into SQLite via `ingestAlert()`
  * Provides RESTful APIs for frontend consumption

### 🔹 Web Frontend (`/frontend`)

  * Built with **HTML5**, **CSS3 (Dark Mode)**, and **JavaScript (ES6)**
  * Periodically fetches `/api/alerts` and updates tables
  * Displays alerts with **color-coded severity**

-----

## 🧱 Tech Stack

| Layer | Technologies |
| ------------ | -------------------------------------------------- |
| **Sensor** | C++17, pcap (Npcap SDK), winsock2 |
| **Backend** | Node.js, Express.js, better-sqlite3, child\_process |
| **Frontend** | HTML5, CSS3, JavaScript (ES6+) |
| **Tooling** | g++ (MinGW), npm, Git |

-----

## ⚙️ Prerequisites

Before setup, ensure the following are installed on your **Windows** system:

1.  **Node.js** (v22.x or later)
2.  **Npcap**
      * Download & install
      * Check the option: *"Install Npcap in WinPcap API-compatible Mode"*
3.  **Npcap SDK**
      * Download and unzip to a permanent location (e.g. `C:\npcap-sdk`)
4.  **C++ Compiler**
      * e.g., `g++` from **MinGW**

-----

## 🧩 Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/ishansaxena012/nids.git
cd nids
```

### 2️⃣ Configure the C++ Build (One-Time Setup)

Edit the Npcap SDK path inside `scripts/build.bat`:

```bat
set SDK_PATH=C:\npcap-sdk
```

Update this path if you installed Npcap SDK elsewhere.

### 3️⃣ Build the Project

```bash
scripts/build.bat
```

This will:

  * Compile the C++ sensor
  * Install all Node.js dependencies

-----

## ▶️ How to Run

### 1️⃣ Start the Platform

```bash
scripts/start.bat
```

  * Backend runs on **[http://localhost:3000](https://www.google.com/search?q=http://localhost:3000)**
  * Frontend runs on **[http://localhost:3001](https://www.google.com/search?q=http://localhost:3001)**

### 2️⃣ View the Dashboard

Open your browser and visit:

👉 [http://localhost:3001](https://www.google.com/search?q=http://localhost:3001)

### 3️⃣ Generate Test Alerts

Your dashboard may initially be silent (normal traffic ignored).
To simulate detections, run:

```bash
ping google.com
```
```bash
ping wikipedia.org
```

You should see **"ICMP (Ping) packet detected"** alerts in real time.

-----

## 🧽 Utility Scripts

| Script | Purpose |
| ------------------------------ | --------------------------------------------------------------------- |
| **`scripts/start.bat`** | Starts backend and frontend servers |
| **`scripts/build.bat`** | Compiles C++ sensor and installs dependencies |
| **`scripts/clear_alerts.bat`** | Clears database tables (`alerts`, `audit_logs`, `notification_queue`) |

-----

## 🧠 Future Enhancements

  * [ ] WebSocket-based real-time updates
  * [ ] ML-based anomaly detection
  * [ ] Email/SMS notifications for high severity alerts
  * [ ] Docker containerization for deployment

-----

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

-----

## 👨‍💻 Author

**Ishan Saxena**
📧 *[06ishansaxena@gmail.com](mailto:06ishansaxena@gmail.com)*
🌐 *[linkedin](https://www.linkedin.com/in/ishan-saxena-62781428b/)*

-----

> *Built with chai using C++, Node.js, and JavaScript.*

