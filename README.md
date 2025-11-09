# WebPort ACME Automation (CSR Mode)

This PowerShell script automates SSL/TLS certificate issuance, installation, renewal, and cleanup for **WebPort** using **ACME (Let’s Encrypt)**.  
It reads CSR and certificate metadata directly from the WebPort SQLite database and updates all certificate values back into WebPort.

> ✅ Supports any ACME DNS plugin, configurable by `-DnsPlugin` and `-PluginArgsFile`.

---

## ✅ Features

✔ Reads **CSR** (and CN/SAN) from WebPort database  
✔ Issues an ACME certificate via **Posh-ACME**  
✔ Supports multiple DNS plugins  
✔ Loads DNS plugin parameters from external file  
✔ Generates and installs `.p12` into WebPort  
✔ Updates WebPort DB: leaf, intermediate, root  
✔ Removes old certificates from the Windows certificate store  
✔ Automatically sets Windows firewall rule for WebPort port  
✔ Restarts WebPort (service or EXE) automatically  
✔ Failsafe mode to wipe all WebPort SSL config  
✔ Validates admin + PowerShell 7+  
✔ Ensures Posh-ACME module is installed  

---

## 🧩 Requirements

| Component | Required |
|----------|----------|
| Windows | ✅ |
| PowerShell 7+ | ✅ |
| Administrator privileges | ✅ |
| Posh-ACME module | Auto-installed |
| OpenSSL | Required for `.p12` build |
| WebPort installation | ✅ |

---

## 🔧 Parameters

| Parameter | Description |
|-----------|-------------|
| `-PfxPass` | Password for `.p12` bundle (mandatory unless `-failsafe`) |
| `-IssueCert` | Requests a certificate using CSR + ACME |
| `-ExportPfx` | Builds `webport.p12` for WebPort |
| `-DnsPlugin` | Which Posh-ACME DNS plugin to use |
| `-PluginArgsFile` | Path to file containing DNS plugin arguments |
| `-ZoneName` | DNS zone name |
| `-ResourceGroup` | Azure example; not required if not Azure |
| `-WebPortDataPath` | WebPort data root |
| `-WebPortProgPath` | WebPort program folder |
| `-failsafe` | Clears SSL from DB, keystore & restarts WebPort |

---
### 1) When requesting ACME certificates, Let’s Encrypt must verify that you control the domain.
If you use DNS-01 challenges, this is done by automatically creating special TXT records under the domain.
To automate this step, Posh-ACME uses DNS plugins.

Each plugin knows how to talk to a specific DNS provider’s API.
https://poshac.me/docs/v4/Plugins/
# 📄 What is `PluginArgsFile`?

`PluginArgsFile` is a configuration file (typically **JSON**) that contains DNS plugin–specific parameters used by **Posh-ACME** when performing ACME DNS-01 validation.

Instead of supplying `-PluginArgs` inline, you store them in a file and load them automatically.

This is useful because:

✅ Keeps credentials out of shell history  
✅ Easier to reuse and maintain  
✅ Good for automation and CI/CD  
✅ Easy to swap DNS providers (Azure, Cloudflare, Route53, etc.)  

---

## Why use `PluginArgsFile`?

Example without PluginArgsFile:

```powershell
New-PACertificate example.com -DnsPlugin Azure -PluginArgs @{
    AZSubscriptionId = "xxxxx"
    AZAccessToken    = "xxxxx"
    AZResourceGroup  = "DNS"
    AZZoneName       = "example.com"
}
```

### 2) Download the script

```powershell
curl "https://raw.githubusercontent.com/demesg/LetsEncryptWebport/refs/heads/main/LetsEncryptWebport.ps1" -o "C:\Temp\LetsEncryptWebport.ps1"
```
