# 👻 GHOSTLINK — Wi‑Fi Security Testing Framework

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/Version-2.0.1-brightgreen.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()
[![Use](https://img.shields.io/badge/Use-Educational%20Only-red.svg)]()

---

## 🧠 Overview

**GHOSTLINK** is a modular Wi‑Fi security testing and network intelligence framework built for **authorised environments, cybersecurity learning, and controlled lab analysis**.

It combines a **false‑positive‑free password testing engine** with a deep reconnaissance suite, delivered through a clean, hacker‑style CLI.

---

## ✨ What Makes It Different

* ✅ **Zero false‑positive architecture** (connection + DHCP IP verification)
* ⚙️ **Hybrid attack pipeline** (dictionary + pattern + brute‑force)
* 🧠 **Full recon suite** after connection (9 specialised modules)
* 💾 **Resume system + encrypted vault storage**
* 🖥️ **Interactive + CLI modes**
* 🔒 **Built with safety constraints in mind**

---

## 🔑 Attack Engine

### Profiles

* Numeric
* Lowercase
* Uppercase
* Mixed Case
* Alphanumeric
* Extended
* Symbols
* Hexadecimal
* Custom Mask

### Capabilities

* Sequential brute‑force (e.g. `00000000` → …)
* Dictionary attack (wordlist support)
* Pattern-based guessing (common passwords, keyboard patterns)
* Hybrid pipeline prioritising likely passwords first
* Configurable timeout, threads, and resume support

---

## 🛡️ Reliability & Safety

* Forces clean Wi‑Fi state before every attempt
* Requires **successful connection + valid DHCP IP lease**
* Rejects stale or partial connections
* Removes invalid cached passwords automatically

---

## 🌐 Reconnaissance Modules

| # | Module                 | Description                            |
| - | ---------------------- | -------------------------------------- |
| 1 | Full Network Recon     | Subnet sweep, ARP, port scan, services |
| 2 | My Device – Deep Info  | Interfaces, IPs, routes, connections   |
| 3 | Network Infrastructure | Gateway, DHCP, NAT, traceroute         |
| 4 | Wireless Analysis      | Signal, channels, security             |
| 5 | External Identity      | Public IP, ISP, DNS                    |
| 6 | Performance            | Latency, jitter, packet loss           |
| 7 | Resources              | SMB, NAS, printers                     |
| 8 | Security Insights      | Ports, firewall, risk score            |
| 9 | Traffic Analysis       | Live connections, stats                |

---

## 🧰 Extra Features

* 🔐 Encrypted password vault (optional)
* 📁 JSON report export
* 🔄 Resume interrupted sessions
* 📊 Live dashboard (speed, attempts, ETA)
* 🌐 Speed test (download; upload via `speedtest-cli`)

---

## 📁 Project Structure

```
ghostlink/
├── core/
├── engine/
├── network/
├── dashboard/
├── storage/
├── cli/
├── main.py
├── run.py
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Requirements

* Python 3.9+

**Windows:** Administrator privileges required
**Linux:** root privileges, `nmcli`, `iw`, `ip`

---

### Installation

```bash
git clone https://github.com/your-repo/ghostlink.git
cd ghostlink
pip install -r requirements.txt
```

---

### Run

```bash
python run.py
```

---

## ⚡ Quick Workflow

1. Scan networks
2. Select authorised target
3. Choose attack profile
4. Configure password range
5. Start attack
6. Run recon modules

---

## 💻 CLI Mode

```bash
python run.py --ssid "MyWiFi" --profile 1 --minlen 4 --maxlen 8 --threads 2
```

### Arguments

| Argument    | Description          |
| ----------- | -------------------- |
| --ssid      | Target SSID          |
| --profile   | Attack profile ID    |
| --charset   | Custom charset       |
| --minlen    | Minimum length       |
| --maxlen    | Maximum length       |
| --wordlist  | Dictionary file      |
| --threads   | Worker threads       |
| --timeout   | Connection timeout   |
| --use-cache | Use saved password   |
| --force     | Skip privilege check |
| --debug     | Verbose logs         |

---

## ⚙️ Configuration Tips

* Start with short lengths (4–6)
* Use wordlists before brute-force
* Keep threads low (1–3)
* Resume is automatic via state file

---

## 🔐 Security & Ethics

✔ Allowed:

* Personal networks
* Lab environments
* Authorised penetration testing

❌ Not Allowed:

* Unauthorised access
* Public or private networks without permission

---

## 🧪 Testing

```bash
pip install pytest
pytest tests/
```

---

## 🐞 Known Limitations

* Slow due to Wi‑Fi handshake limits
* Linux support partial
* Requires compatible adapter

---

## 📌 Roadmap

* GUI version (Kivy)
* Plugin system
* Real-time dashboard
* WPA3 analysis support
* Distributed attacks

---

## 📄 License

Educational use only.

---

## 👨‍💻 Author

**Sahan Pramuditha**


---

## ⭐ Support

* ⭐ Star the repo
* 🍴 Fork it
* 🧠 Suggest improvements

---

> "Powerful tools require responsible minds."
