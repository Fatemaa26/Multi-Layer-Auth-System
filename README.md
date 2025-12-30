## 🔐 Multi-Layer Cryptographic Authentication System

## 🖥️ User Interface Preview

### Login Portal
![Login Preview](Login.jpeg)

### User Registration
![Register Preview](Registeration.jpeg)


A professional-grade secure portal built with Python and CustomTkinter. This project demonstrates a "Defense in Depth" strategy by using a 4-layer cryptographic pipeline to protect user credentials.

🛠 Features
4-Layer Security Pipeline: Every password is processed through a sequential chain of SHA-512, DES, AES, and RSA.

Modern UI: Sleek, dark-mode "Secure Portal" interface with an aqua-accent aesthetic.

Real-time Strength Meter: Instant visual feedback on password complexity.

Self-Healing Setup: Automatically generates cryptographic keys and the local vault file on the first run.

⚙️ How It Works (The Pipeline)
SHA-512 Hashing: The password is first hashed into a one-way digest.

DES Encryption: The hash is encrypted using Data Encryption Standard.

AES Encryption: A layer of AES is added for modern symmetric security.

RSA Encryption: The data is finally wrapped in an Asymmetric layer before being stored in the user_vault.txt.

🚀 How to Run
1- Clone the repo:
git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME](https://github.com/Fatemaa26/Multi-Layer-Auth-System).git

2- Install dependencies:
pip install -r requirements.txt

3- Launch the App:
python auth_system.py
