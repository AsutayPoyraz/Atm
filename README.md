# 🏦 ATM 1.0 — Digital Banking and ATM Simulation

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

A full-stack, educational ATM and digital banking simulation built with modern web technologies and FastAPI, running as a single-file application.

</div>

---

## ✨ Features

* **🔐 Secure Authentication:** PBKDF2-HMAC-SHA256 based password hashing and session management (Session TTL).
* **💰 Comprehensive Account Management:** Real-time balance tracking across checking and savings accounts.
* **💸 Cash Withdrawal & Deposit:** ATM banknote simulation (200 TL, 100 TL, etc.) with daily withdrawal/transfer limits enforcement.
* **⇄ Inter-Account Transfers:** Instant money transfer simulation using Turkish ID Numbers (TCKN).
* **▦ Bill Payments:** Simulation for electricity, water, natural gas, and internet bills.
* **▤ Transaction History & Reporting:** Advanced filtering, searching, pagination, and **CSV export** support.
* **⚙ Security Settings:** PIN change functionality and account lockout protection after consecutive failed attempts.
* **📱 Modern SPA Interface:** Responsive, dark/light theme-supported modern embedded HTML/CSS/JS frontend.

---

## 👥 Demo Accounts

The following test accounts are automatically seeded into the database upon the first launch of the application:

| Account Name | Turkish ID Number (TCKN) | PIN |
| :--- | :--- | :--- |
| **Demo User** | `11111111111` | `1234` |
| **Ayşe Demir** | `22222222222` | `0000` |

---

## 🚀 Installation & Running

Follow these steps to run the project locally:

### 1. Prerequisites
Make sure **Python 3.8+** is installed on your system.

### 2. Clone or Download
Download or clone the project files to your local machine (e.g., `Atm 1.0.py`).

### 3. Install Dependencies
Open your terminal or command prompt and run the following command:
```bash
pip install fastapi uvicorn sqlalchemy pydantic


5. Open in Browser
Open your browser and navigate to:
👉 http://127.0.0.1:8000

🛠️ Tech Stack
Backend: Python, FastAPI, Uvicorn, SQLAlchemy, Pydantic

Database: SQLite (atm_v2.db)

Frontend: HTML5, CSS3 (Modern Flexbox/Grid & Custom Properties), Vanilla JavaScript (SPA Architecture)

Security: hashlib, hmac, secrets (PBKDF2 Hashing)

⚠️ Legal / Educational Disclaimer
This application is designed solely for educational, portfolio, and prototype development purposes. It has no affiliation with any real banking systems, and real financial data or genuine TCKNs must never be used.

📄 License
This project is open-source and shared for educational purposes. Feel free to modify, enhance, and use it as you wish.

