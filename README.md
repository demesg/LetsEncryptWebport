# WebPort ACME Automation Script

This script automates SSL certificate issuance, renewal, installation, and maintenance for **Kiona WebPort** using **Let’s Encrypt / ACME** and **Posh-ACME**.

---

## 📌 Features

- CSR‑based ACME certificate issuance  
- DNS‑01 validation using any Posh-ACME DNS plugin  
- Automatic certificate chain insertion into WebPort SQLite DB  
- Creation of WebPort-compatible `webport.p12`  
- Optional installation of certificate into Windows certstore  
- Automatic firewall rule management  
- Built‑in failsafe mode to fully reset SSL state  
- Scheduled Task creation (PowerShell 7)  
- E‑mail reporting for both success and failure  
- Secure SecretStore integration  

---

## ⚙ Parameter Overview

### `-failsafe`
Resets SSL-related database fields, deletes P12, removes matching certificates, and restarts WebPort.  
**Cannot be combined with ACME-related parameters.**

### `-IssueCert`
Requests or renews ACME certificates using the CSR stored in WebPort.

### `-InstallPfx`
Builds and installs `webport.p12`.

### `-DnsPlugin`
Specifies Posh-ACME DNS plugin (e.g., Azure, Cloudflare, AcmeDNS).

### `-Sendmail`
Sends a report email after execution (supports multiple recipients via `;`).

### `-CreateScheduledTask`
Creates a Scheduled Task with identical parameters and working directory.

---

## 🔐 SecretStore Usage

Used to store:

- `PluginArgs` – DNS plugin configuration  
- `PfxPass` – password for the P12 file  
- `SmtpPwd` – SMTP password  

The script automatically:

1. Ensures SecretManagement & SecretStore modules exist  
2. Registers and sets SecretStore as default vault  
3. Initializes the vault if necessary  
4. Unlocks it using `securePassword.xml`  
5. Loads required secrets  

Example:

```powershell
Set-Secret -Name PluginArgs -Secret $pArgs
Set-Secret -Name PfxPass   -Secret "MyStrongPassword"
Set-Secret -Name SmtpPwd   -Secret "S3cur3!"
```

List secrets:

```powershell
Get-SecretInfo
```

---

## 🧩 DNS Plugin Configuration

Documentation:  
https://poshac.me/docs/v4/Plugins/

Show plugin guides:

```powershell
Get-PAPlugin -Plugin Azure      -Guide
Get-PAPlugin -Plugin Cloudflare -Guide
Get-PAPlugin -Plugin AcmeDns    -Guide
```

---

## 🔄 ACME Certificate Flow

1. CSR is created through WebPort GUI  
2. Script reads CSR and submits ACME order  
3. DNS‑01 challenge performed  
4. Certificate chain retrieved  
5. WebPort DB updated:
   - SSLCAPC (leaf)  
   - SSLCAIC (intermediate)  
   - SSLCARC (root)  
6. P12 file created  
7. Optional: certificate installed into certstore  
8. WebPort restarted  

---

## 🧯 Failsafe Mode

Clears:

- SSLCSR  
- SSLPPK  
- SSLCAPC  
- SSLCAIC  
- SSLCARC  
- SSLCP  

Removes P12 and matching installed certificates.  
Restarts WebPort.

---

## 📬 Email Reporting

If `-Sendmail` is provided:

### When errors are detected:
Subject:  
`<CN> - Problem renewing certificate`

### When everything succeeded:
Subject:  
`<CN> - Certificate renewed`

Log entries scanned for:

- exception  
- error  
- fail  
- timeout  
- denied  
- invalid  
- could not  
- not found  

SMTP settings must exist in WebPort DB.

---

## ⏱ Scheduled Task Creation

The script creates a weekly task:

- Runs with current user (`S4U` logon type)  
- Uses PowerShell 7  
- Uses same parameters as the script was executed with  
- Working directory is the script's folder  
- Execution time limit: **5 minutes**  

---

## 📜 Requirements

- PowerShell 7+  
- Administrator privileges  
- WebPort installed  
- CSR created in WebPort GUI  
- DNS plugin parameters configured in SecretStore  

---

## 👤 Author

**Magnus Ardström**  
Version: **1.0.0**  
Last Updated: **2025‑11‑09**

---

## 📁 Recommended Repository Structure

```
/WebPort-ACME/
│
├─ LetsEncryptWebPort.ps1
├─ README.md
├─ securePassword.xml
└─ pluginArgs.json
```

---

## 📝 Notes

- ENSURE SAN entries are present in the CSR; missing SAN causes  
  `asn1: syntax error: sequence truncated`  
- Logging is stored in `ScriptName-logs/` for 100 days  
- WebPort may run as service or standalone EXE; script handles both  
- OpenSSL is required for P12 construction  

