# WebPort ACME Automation (CSR Mode)

This PowerShell script automates SSL/TLS certificate issuance, renewal, installation, and cleanup for **Kiona WebPort** using **ACME (Let’s Encrypt)**.

It reads CSR and certificate metadata directly from WebPort’s SQLite database, performs certificate requests via ACME, updates certificate fields back into WebPort, optionally installs certificates into the Windows LocalMachine store, and can restart WebPort automatically.

The script supports all Posh-ACME DNS plugins and can use plugin arguments loaded from an external configuration file.

---

## ✅ Features

- Reads CSR and CN from WebPort DB
- Generates ACME certificates using Posh-ACME
- Supports multiple DNS plugins (Azure, Cloudflare, Route53, etc.)
- Loads DNS plugin arguments from an external file
- Stores leaf/intermediate/root certs into WebPort DB
- Builds WebPort-compatible P12 file
- Installs certificate into LocalMachine\My
- Removes old certificates from Windows certificate store
- Ensures Windows firewall allows WebPort traffic
- Automatically restarts WebPort after installation
- Failsafe mode resets SSL state
- Confirms PowerShell 7+
- Confirms administrative privileges
- Installs Posh-ACME module if missing

---

## 🧩 Requirements

| Component | Required | Notes |
|-----------|----------|-------|
| Windows OS | Yes | |
| PowerShell 7+ | Yes | Must run via pwsh |
| Administrator rights | Yes | Required for certificate + firewall |
| Posh-ACME module | Yes | Auto-installed if missing |
| OpenSSL | Yes | Required for .p12 file |
| WebPort installed | Yes | |

Also confirm:
- `$PSVersionTable.PSVersion` is ≥ 7
- `openssl` is available

---

## 📦 Installation

https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5

Download example:

curl https://raw.githubusercontent.com/demesg/LetsEncryptWebport/refs/heads/main/LetsEncryptWebport.ps1 -o C:\Temp\LetsEncryptWebport.ps1

Run using PowerShell 7:

C:\Temp\LetsEncryptWebport.ps1

---

## 🔧 Parameters

| Parameter | Description |
|-----------|-------------|
| PfxPass | Password for .p12 bundle (mandatory unless failsafe) |
| failsafe | Clears SSL config, no ACME |
| IssueCert | Requests certificate via ACME using CSR |
| ExportPfx | Builds webport.p12 and installs it |
| CreateScheduledTask | Creates weekly certificate renewal task |
| DnsPlugin | Name of Posh-ACME DNS plugin |
| PluginArgsFile | Path to JSON file containing plugin arguments |
| ZoneName | DNS zone name |
| ResourceGroup | Azure resource group (if Azure plugin) |
| WebPortDataPath | WebPort data directory |
| WebPortProgPath | WebPort program directory |

---

## 🌐 DNS Plugin Overview

When issuing ACME certificates, Let’s Encrypt must verify domain ownership.

If DNS-01 validation is used, a TXT record is created automatically:
`_acme-challenge.example.com`

Posh-ACME DNS plugins:
- Handle provider-specific APIs
- Create & remove TXT records
- Enable automatic, unattended renewals

Example DNS providers:
- Azure
- Cloudflare
- AWS Route53
- Google
- AcmeDns
- Hetzner
- TransIP
- And many more

To list available plugins:
Get-PAPlugin

To view specific plugin details:
Get-PAPlugin -Plugin Azure -Guide

Documentation:
https://poshac.me/docs/v4/Plugins/

---

## 📄 What is PluginArgsFile?

PluginArgsFile is a text file (JSON format recommended) that stores DNS provider configuration used by Posh-ACME to perform DNS-01 validation.

It holds sensitive values such as:
- Subscription IDs
- API tokens
- Resource Group
- DNS zone information

Advantages:
- Keeps secrets out of command arguments
- Avoids exposure in PowerShell history
- Easy to rotate credentials
- Allows changing DNS provider without script change
- More automation-friendly

Example JSON structure:
{
  "AZSubscriptionId": "xxxxx",
  "AZAccessToken": "xxxxx",
  "AZResourceGroup": "DNS",
  "AZZoneName": "example.com"
}

Usage example:
.\LetsEncryptWebport.ps1 -IssueCert -DnsPlugin Azure -PluginArgsFile C:\secure\plugin.json -PfxPass "secret"

---

## 🏗 Usage Examples

Request certificate and build P12:
.\LetsEncryptWebport.ps1 -IssueCert -ExportPfx -DnsPlugin Azure -PluginArgsFile C:\secure\plugin.json -PfxPass "secret"

Use Cloudflare:
.\LetsEncryptWebport.ps1 -IssueCert -DnsPlugin Cloudflare -PluginArgsFile C:\secure\cf.json -PfxPass "secret"

Failsafe cleanup:
.\LetsEncryptWebport.ps1 -failsafe

Create weekly task:
.\LetsEncryptWebport.ps1 -CreateScheduledTask

---

## 🔍 WebPort Database Fields

The script reads and/or updates these WebPort DB keys:

| Key | Description |
|-----|-------------|
| SSLCN | Common Name + SAN list |
| SSLCSR | CSR data |
| SSLPPK | Private key |
| SSLCAPC | Leaf certificate |
| SSLCAIC | Intermediate certificate |
| SSLCARC | Root certificate |
| SSLCP | CSR password |

---

## 🧨 Failsafe Mode

Failsafe mode resets SSL configuration safely when certificate/DB state is corrupted.

Actions performed:

- Clears SSL DB keys:
  SSLCSR  
  SSLPPK  
  SSLCAPC  
  SSLCAIC  
  SSLCARC  
  SSLCP  

- Removes webport.p12
- Removes matching certificates from LocalMachine\My
- Restarts WebPort

No ACME requests occur.  
PfxPass must NOT be used with failsafe.

Example:
.\LetsEncryptWebport.ps1 -failsafe

---

## ⏰ Scheduled Weekly Renewal

The script can create an automated weekly scheduled task that renews certificates and rebuilds P12.

- Runs PowerShell 7
- Runs elevated
- Executes IssueCert + ExportPfx paths

Trigger: Weekly

Generate using:
.\LetsEncryptWebport.ps1 -CreateScheduledTask

---

## ⚠ Important Notes

- Must run under PowerShell 7+
- Must run elevated (Administrator)
- CSR must first be created via WebPort GUI
- PfxPass is required unless in failsafe
- DNS plugin + PluginArgsFile required for ACME
- OpenSSL must be installed
- Certificates installed into LocalMachine\My

---

## 👤 Author & Revision

| Field | Value |
|-------|-------|
| Author | Magnus Ardström |
| Version | 1.0.0 |
| Last Updated | 2025-11-09 |

---

## ✅ Summary

This script automates full certificate lifecycle management for WebPort:

1. Reads CSR from WebPort
2. Performs ACME certificate request
3. Updates WebPort DB with leaf/intermediate/root
4. Builds P12 and installs it
5. Cleans old Windows certs
6. Opens firewall port
7. Restarts WebPort
8. Can schedule recurring renewals
9. Failsafe recovery available

It provides complete end-to-end automated TLS support for WebPort.

