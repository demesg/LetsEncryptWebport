# WebPort ACME Automation (CSR Mode)

This PowerShell script automates SSL/TLS certificate issuance for **Kiona WebPort** using **ACME (Let’s Encrypt)**.

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
- Server port  
- Scheduled Task automation  
- SecretStore integration for secure parameters  
- Full logging and email notification support  

---

# 1. Installation & Requirements

## PowerShell 7
This script **requires PowerShell 7+**.

Install:  
https://learn.microsoft.com/powershell/scripting/install/installing-powershell

### Install Required Modules (Run as Administartor)

#### **Posh-ACME**
```powershell
Install-Module Posh-ACME -Scope AllUsers -Force
```

#### **SecretStore**
```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope AllUsers -Force
Install-Module Microsoft.PowerShell.SecretStore      -Scope AllUsers -Force
```

#### **If Using Azure DNS**
```powershell
Install-Module Az.Accounts    -Scope AllUsers -Force
Install-Module Az.Resources   -Scope AllUsers -Force
Install-Module Az.Network     -Scope AllUsers -Force
```

## OpenSSL Requirement

The script uses OpenSSL when building the `.p12`.

Install Win64OpenSSL Light from:  
```powershell
$u="https://slproweb.com/download/Win64OpenSSL_Light-3_6_0.exe"; $f="$env:TEMP\openssl.exe"; Invoke-WebRequest $u -OutFile $f; Start-Process $f -ArgumentList "/silent","/verysilent","/sp-","/suppressmsgboxes" -Wait; Remove-Item $f -Force
```
https://slproweb.com/products/Win32OpenSSL.html

---

# 2. DNS Plugin Configuration

The script supports all official Posh-ACME dns-01 plugins.  
Full documentation:  
https://poshac.me/docs/v4/Plugins/

To list all plugins and specific guides:
```powershell
Get-PAPlugin
Get-PAPlugin Azure -Guide
```

### Download the Script

You can fetch the latest version directly from GitHub:

```powershell
curl "https://raw.githubusercontent.com/demesg/LetsEncryptWebport/refs/heads/main/LetsEncryptWebport.ps1" `
  -o "C:\Script\LetsEncryptWebport.ps1"
```

## SecretStore Usage

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
# **WebPort Setup**
To continue, you must create a CSR in the WebPort GUI. Exactly like this:

1. Log in to **WebPort**
2. Navigate to: **System Settings → Server → SSL Certificate**
3. Enter:
   - **Common Name (CN)** = (i.e. webport.xyz.com )
   - **SAN (Subject Alternative Names)** additional names are needed (i.e. webport2.xyz.com )
   - **Password** (store for later use in PfxPass) 
4. Click **Save**
5. Go back to **SSL Certificate**
6. Click **Create CSR**

The CSR will then be automatically stored in the database (`settings → SSLCSR`).
Common Name (CN) needs to be in the domain DNS plugin can manage.
Run the script after the CSR has been created.



---

# Examples

### Request + Install Certificate
```powershell
.\LetsEncryptWebport.ps1 -IssueCert -InstallPfx -DnsPlugin Azure -Sendmail you@example.com 
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
