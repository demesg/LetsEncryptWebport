# WebPort ACME Automation (CSR Mode)

This PowerShell script automates SSL/TLS certificate issuance, installation, renewal, and cleanup for **WebPort** using **ACME (Let’s Encrypt)**.

---

## Features

- Reads CSR (and CN/SAN) from WebPort database  
- Issues certificate via Posh-ACME (DNS-01)  
- Supports any DNS plugin  
- Updates WebPort DB with:
  - Leaf certificate  
  - Intermediate  
  - Root  
- Builds WebPort-compatible `.p12`  
- Installs certificate into `LocalMachine\My`  
- Ensures firewall rule exists  
- Restarts WebPort service/EXE  
- Failsafe mode clears all SSL data  
- Scheduled Task automation  
- SecretStore integration for secure parameters  
- Full logging and email notification support  

---

# Installation & Requirements

## PowerShell 7
This script **requires PowerShell 7+**.

Install:  
https://learn.microsoft.com/powershell/scripting/install/installing-powershell

---

# OpenSSL Requirement

The script uses OpenSSL when building the `.p12`.

Install from:  
https://slproweb.com/products/Win32OpenSSL.html

---

## Install Required Modules

### **Mandatory**
```powershell
Install-Module Posh-ACME -Scope AllUsers -Force
```

### **If Using Azure DNS**
```powershell
Install-Module Az.Accounts    -Scope AllUsers -Force
Install-Module Az.Resources   -Scope AllUsers -Force
Install-Module Az.Network     -Scope AllUsers -Force
```

### **Using SecretStore**
```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope AllUsers -Force
Install-Module Microsoft.PowerShell.SecretStore      -Scope AllUsers -Force
```

---

# Download the Script

You can fetch the latest version directly from GitHub:

```powershell
curl "https://raw.githubusercontent.com/demesg/LetsEncryptWebport/refs/heads/main/LetsEncryptWebport.ps1" `
  -o "C:\Script\LetsEncryptWebport.ps1"
```

---

# DNS Plugin Configuration

The script supports all official Posh-ACME DNS plugins.  
Full documentation:  
https://poshac.me/docs/v4/Plugins/

To list all plugins:
```powershell
Get-PAPlugin
```

Example Azure plugin argument structure:
```powershell
$pluginArgs = @{
    AZSubscriptionId = "xxxx"
    AZAccessToken    = "xxxx"
    AZResourceGroup  = "DNS"
    AZZoneName       = "domain.tld"
}
```

---

# PluginArgsFile

You may store DNS plugin parameters in a JSON file.

Example JSON:
```json
{
  "AZSubscriptionId": "xxxx",
  "AZAccessToken": "xxxx",
  "AZResourceGroup": "DNS",
  "AZZoneName": "domain.tld"
}
```

---

# SecretStore Usage

Store sensitive values securely:
```powershell
Set-Secret -Name PluginArgs -Secret $pluginArgs
Set-Secret -Name PfxPass -Secret "MyStrongPassword"
Set-Secret -Name SmtpPwd -Secret "S3cur3!"
```

List stored secrets:
```powershell
Get-SecretInfo
```

---

# Examples

### Request + Install Certificate
```powershell
.\LetsEncryptWebport.ps1 -IssueCert -InstallPfx
```

### Cleanup / Reset SSL Data
```powershell
.\LetsEncryptWebport.ps1 -failsafe
```

### Create Scheduled Task
```powershell
.\LetsEncryptWebport.ps1 -IssueCert -InstallPfx -DnsPlugin Azure -Sendmail you@example.com -CreateScheduledTask 
```

---

# Logging

All script runs produce timestamped logs under:
```
<ScriptPath>\<ScriptName>-logs```

---

# Email Notification Support

If `-Sendmail you@example.com` is provided:
- The script automatically analyzes logs  
- Sends success/failure reports  
- Requires SMTP settings inside WebPort DB

---

# Failsafe Mode

`-failsafe`:
- Clears SSLCSR, SSLPPK, SSLCAPC, SSLCAIC, SSLCARC, SSLCP  
- Deletes webport.p12  
- Removes matching certificates  
- Resets WebPort port  
- Restarts WebPort  

---

# Author

**Original Author:** Magnus Ardström  
Version 1.0.0 — 2025-11-09  
