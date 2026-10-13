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

#### **If scripts is disabled**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
```

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

Install Win64 OpenSSL Light (latest 3.x). Older installers are removed from slproweb.com, so the command looks up the current version in slproweb's official hash list and verifies the SHA256 before installing:
```powershell
$files = (Invoke-RestMethod "https://raw.githubusercontent.com/slproweb/opensslhashes/master/win32_openssl_hashes.json").files.PSObject.Properties.Value
$pkg = $files | Where-Object { $_.bits -eq 64 -and $_.light -and $_.installer -eq "exe" -and $_.arch -eq "INTEL" -and $_.basever -like "3.*" -and -not $_.subver } |
    Sort-Object { [version]$_.basever } | Select-Object -Last 1
$f = "$env:TEMP\openssl.exe"
Invoke-WebRequest $pkg.url -OutFile $f
if ((Get-FileHash $f -Algorithm SHA256).Hash -ne $pkg.sha256) { Remove-Item $f -Force; throw "SHA256 mismatch" }
Start-Process $f -ArgumentList "/silent","/verysilent","/sp-","/suppressmsgboxes" -Wait
Remove-Item $f -Force
```
Manual download: https://slproweb.com/products/Win32OpenSSL.html (choose **Win64 OpenSSL v3.x Light**, EXE).

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
Follow guide to create the $pArgs variable in Powershell.

Or use Deploy-PoshAcmeAzure script to setup:
```powershell
curl "https://raw.githubusercontent.com/demesg/LetsEncryptWebport/refs/heads/main/Deploy-PoshAcmeAzure.ps1" -o "C:\Script\Deploy-PoshAcmeAzure.ps1"
cd c:\script
.\Deploy-PoshAcmeAzure.ps1 -Domain **MyAzureDomain.com**
$pArgs = @{}; (Get-Content 'C:\Script\PoshAcme-AzureDns-PluginConfig.json' -Raw | ConvertFrom-Json).PluginArgs.PSObject.Properties | ForEach-Object { $pArgs[$_.Name] = $_.Value }
```


# 3. The Script 
### Download the Script

You can fetch the latest version directly from GitHub:

```powershell
curl "https://raw.githubusercontent.com/demesg/LetsEncryptWebport/refs/heads/main/LetsEncryptWebport.ps1" `
  -o "C:\Script\LetsEncryptWebport.ps1"
```
Make sure UTF-8 with bom is used .


# 4. WebPort Setup

To continue, you must create a CSR in the WebPort GUI. Exactly like this:

1. Log in to **WebPort**
2. Navigate to: **System Settings → Server → SSL Certificate**
3. Enter:
   - **Common Name (CN)** = (i.e. webport.**MyAzureDomain.com** )
   - **SAN (Subject Alternative Names)** additional names are needed (i.e. webport2.**MyAzureDomain.com** )
   - **Password** (store this value for later use as `PfxPass`)
4. Click **Save**
5. Go back to **SSL Certificate**
6. Click **Create CSR**

The CSR will then be automatically stored in the database (`settings → SSLCSR`).
The password entered in WebPort is stored by WebPort as `SSLCP`. Use the same password for the SecretStore secret named `PfxPass`; the script uses `PfxPass` when creating and importing `webport.p12`.
Common Name (CN) needs to be in the domain DNS plugin can manage.
Run the script after the CSR has SecretStore has been created.

> **Note:** Always fill in **SAN**, even with a single name (use the same value as CN). A CSR created without SAN is rejected by Let's Encrypt — see [Troubleshooting](#troubleshooting).

Run script to initialize Secretstore:

```powershell
cd c:\script
.\LetsEncryptWebport.ps1
```
Provide a password for SecretStore. 
An Exception is expected now.

---

# 5 SecretStore setup

Store sensitive values securely:
```powershell
Set-Secret -Name PluginArgs -Secret $pArgs
Set-Secret -Name PfxPass -Secret "same-password-used-when-creating-the-CSR-in-WebPort"

Set-Secret -Name SmtpPwd -Secret "SMTPPassword!"
```
List stored secrets:
```powershell
Get-SecretInfo
```

# 6 Run Examples

`-ServerPort` is only needed to **change** WebPort's port. If omitted, the port in `webport.conf` is used and left unchanged.

If WebPort is not installed in the default folders (`C:\Program Files\WebPort` and `C:\ProgramData\WebPort`), pass `-WebPortProgPath` and `-WebPortDataPath`. The script aborts if `WebPortServer.exe`, `webport.conf` or `db\webport.sqlite` cannot be found.

### Request + Install Certificate
```powershell
.\LetsEncryptWebport.ps1 -IssueCert -InstallPfx -DnsPlugin Azure
```

### Change port to 443 + Request + Install Certificate
```powershell
.\LetsEncryptWebport.ps1 -IssueCert -InstallPfx -DnsPlugin Azure -ServerPort 443 -Sendmail you@example.com
```

### Non-default WebPort folders
```powershell
.\LetsEncryptWebport.ps1 -IssueCert -InstallPfx -DnsPlugin Azure -WebPortProgPath "E:\WebPort" -WebPortDataPath "E:\WebPort\programdata"
```

### Cleanup / Reset SSL Data
```powershell
.\LetsEncryptWebport.ps1 -failsafe
```

### Create Scheduled Task
```powershell
.\LetsEncryptWebport.ps1 -CreateScheduledTask -DnsPlugin Azure -Sendmail you@example.com
```
Runs all checks (SecretStore, Posh-ACME, WebPort DB/CSR, firewall) and creates a weekly task (Sunday 02:00) that runs `-IssueCert -InstallPfx`. No certificate is issued when the task is created. The task does not include `-ServerPort`; it uses the port in `webport.conf`. Add `-WebPortProgPath`/`-WebPortDataPath` if WebPort is not in the default folders — they are stored in the task.

---

# Logging

All script runs produce timestamped logs under:

<ScriptPath>\<ScriptName>-logs

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

# Troubleshooting

### `Error parsing certificate request: asn1: syntax error: sequence truncated`

DNS validation succeeds, but finalizing the order fails with:

```
WARNING: No Certficate Attributes found in CR.
...
"type": "urn:ietf:params:acme:error:malformed",
"detail": "Error parsing certificate request: asn1: syntax error: sequence truncated"
```

**Cause:** The CSR generated by WebPort lacks the PKCS#10 `attributes` field. WebPort omits it when no SAN (Alternative Names) is entered. Posh-ACME accepts the CSR, but Let's Encrypt rejects it as malformed.

**Fix:**
1. In WebPort, go to **System Settings → Server → SSL Certificate**
2. Enter **SAN** — at minimum the same name as CN (e.g. `webport.MyAzureDomain.com`). Fill in **State/Province** as well.
3. Click **Save**, then **Create CSR**
4. Run the script again

---

# Version History

| Version | Date | Changes |
|---|---|---|
| 1.4.0 | 2026-10-13 | `-ServerPort` no longer defaults to 8090 — the port in `webport.conf` is kept unless `-ServerPort` is given explicitly. Script aborts early if WebPort is not found in `-WebPortProgPath`/`-WebPortDataPath`. Scheduled task no longer stores `-ServerPort`; time limit raised from 5 to 30 minutes. Fixed certificate lookup when `SSLCN` contains SAN (caused renewal on every run). Documented the `asn1: sequence truncated` CSR error. OpenSSL install command now resolves the latest 3.x version (old link returned 404). Fixed cmdlet name `Set-DefaultSecretVault` → `Set-SecretVaultDefault`. Supports SecretStore configured without password (`Authentication = None`). |
| 1.3.0 | 2026-06-04 | Support for `Microsoft.Data.Sqlite` (newer WebPort versions), with fallback to `System.Data.SQLite`. Documentation for Azure DNS, SecretStore, CN/SAN and port 443. |
| 1.2.0 | 2026-03-03 | `-CreateScheduledTask` (weekly renewal via PowerShell 7). OpenSSL check with automatic VC++ x64 runtime install. SMTP password read from SecretStore (`SmtpPwd`). Added `Deploy-PoshAcmeAzure.ps1`. |
| 1.1.1 | 2025-11-18 | Fixes. |
| 1.1.0 | 2025-11-17 | Major rework of the script. |
| 1.0.0 | 2025-11-09 | Initial release. |

---

# Author

**Original Author:** Magnus Ardström  
Current version: 1.4.0 — 2026-10-13  
