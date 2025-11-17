<#
.SYNOPSIS
Automates SSL certificate management for Kiona WebPort using ACME/Let’s Encrypt.

.DESCRIPTION
This script performs end-to-end certificate handling for WebPort:

Normal mode ("Normal" ParameterSet):
  • Reads CSR + CN from WebPort SQLite database
  • Requests certificate via ACME (e.g. Let’s Encrypt) based on existing CSR
  • Uses any Posh-ACME DNS plugin (default: Azure)
  • Updates certificate chain (leaf / intermediate / root) in WebPort database
  • Builds WebPort-compatible P12 file
  • Installs certificate into LocalMachine\My (performed in InstallPfx step)
  • Ensures firewall port is enabled
  • Requires PfxPass in Normal mode

Failsafe mode ("FailSafe" ParameterSet):
  • Resets SSL-related database fields:
        SSLCSR, SSLPPK, SSLCAPC, SSLCAIC, SSLCARC, SSLCP
  • Removes `webport.p12`
  • Removes matching certificates from certstore
  • Restarts WebPort
  • Must NOT be combined with PfxPass
  • Performs NO ACME actions

SecretStore is used to store the script’s sensitive parameters.
  1. The SecretStore modules are installed (SecretManagement + SecretStore)
  2. A vault is registered and set as the default
  3. The SecretStore is initialized if it does not already exist
  4. The unlock password is stored in an XML file (e.g., securePassword.xml)
  5. SecretStore is automatically unlocked during script execution
  6. Secrets are read from the vault:
    • PluginArgs – DNS plugin parameters for ACME/Posh-ACME
    • PfxPass – password for the WebPort .p12 file
    • SmtpPwd – password for the SMTP account

.EXAMPLE
# Adding DNS plugin arguments to SecretStore:
$pArgs = @{
    AZSubscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    AZTenantId       = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    AZAppUsername    = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
    AZCertThumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    AZResourceGroup  = "DNS"
    AZZoneName       = "example.com"
}
Set-Secret -Name PluginArgs -Secret $pArgs

.EXAMPLE
# Adding the password for the WebPort PFX:
Set-Secret -Name PfxPass -Secret "MyStrongPassword"

.EXAMPLE
# Adding the SMTP password:
Set-Secret -Name SmtpPwd -Secret "S3cur3!"

.EXAMPLE
# Listing all secrets stored in SecretStore:
Get-SecretInfo

.EXAMPLE
# Retrieving a secret:
Get-Secret -Name PluginArgs -AsPlainText

.EXAMPLE
# Removing a secret:
Remove-Secret -Name PluginArgs

.EXAMPLE
# Resetting the entire SecretStore vault:
Unregister-SecretVault -Name SecretStore
Remove-Item "$env:LOCALAPPDATA\Microsoft\PowerShell\secretmanagement\secretstore" -Recurse -Force


DNS PLUGIN SUPPORT
The script supports any DNS plugin via Posh-ACME:

    -DnsPlugin "Azure"
    -DnsPlugin "Cloudflare"
    -DnsPlugin "Route53"
    -DnsPlugin "AcmeDns"
    …

Plugin-specific arguments can be provided via:

    -PluginArgs @{ Key = "Value"; … }

Example for Azure (auto-population is also supported):
    $pluginArgs = @{
        AZSubscriptionId = "xxxx"
        AZAccessToken    = "xxxx"
        AZResourceGroup  = "DNS"
        AZZoneName       = "domain.tld"
    }

Plugin guide:
    Get-PAPlugin -Plugin Azure      -Guide
    Get-PAPlugin -Plugin Cloudflare -Guide
    Get-PAPlugin -Plugin AcmeDns    -Guide

Each plugin will list which fields are required in PluginArgs.

ACME PROCESS
  • CSR must first be generated in the WebPort GUI
  • The script uses the CSR + ACME to obtain a new certificate
  • Leaf, intermediate, and root certificates are stored in WebPort DB
  • Private key is retrieved either from certstore or the database (fallback)

NOTES
  • Requires PowerShell 7+
  • Requires administrative privileges
  • Initial CSR must be created in WebPort GUI
  • Default DNS plugin: Azure, but user may change via -DnsPlugin
  • Only InstallPfx installs the certificate into certstore

PARAMETERS
  -failsafe
      Resets SSL data without ACME. Must NOT be combined with other params.

  -IssueCert
      Requests/renews certificate via ACME using the existing CSR.

  -InstallPfx
      Builds webport.p12 and installs certificate into certstore.

  -DnsPlugin
      DNS plugin used for ACME challenge. Default: "Azure".
      List available plugins:
          Get-PAPlugin

  -PluginArgs
      HashTable with plugin-specific parameters.
      Example:
          -PluginArgs @{ CFToken = "xxxxx" }

  -PfxPass
      Password for the .p12 archive. Mandatory in Normal mode.

  -ZoneName
      DNS zone used by some plugins (e.g. Azure).

  -ResourceGroup
      DNS resource group, used by Azure.

.EXAMPLE
PS> .\LetsEncryptWebport.ps1 -IssueCert -InstallPfx -PfxPass "secret"

.EXAMPLE
PS> .\LetsEncryptWebport.ps1 -IssueCert -DnsPlugin "Cloudflare" `
       -PluginArgs @{ CFToken = "xxxx" } `
       -PfxPass "password"

.EXAMPLE
PS> Get-PAPlugin -Plugin Azure -Guide

.EXAMPLE
PS> .\LetsEncryptWebport.ps1 -failsafe

.AUTHOR
    Original Author:  Magnus Ardström  

.REVISION
    Version:          1.0.0
    Last Updated:     2025-11-09
#>


[CmdletBinding(DefaultParameterSetName="Normal")]
param(
    [Parameter(ParameterSetName="FailSafe", Mandatory=$true)]
    [switch]$failsafe,

    [Parameter(ParameterSetName="CreateScheduledTask", Mandatory=$true)]
    [switch]$CreateScheduledTask,

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [string]$WebPortDataPath = "C:\ProgramData\WebPort",

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [string]$WebPortProgPath = "C:\Program Files\WebPort",

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [int]$ServerPort = "8090",

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [switch]$IssueCert,

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [switch]$InstallPfx,

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [string]$DnsPlugin,

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [string]$PluginArgsFile,

    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [Parameter(ParameterSetName="CreateScheduledTask")]
    [string]$Sendmail  

)

$banner = @'
  _          _       ______                             _    __          __  _     _____           _   
 | |        | |     |  ____|                           | |   \ \        / / | |   |  __ \         | |  
 | |     ___| |_ ___| |__   _ __   ___ _ __ _   _ _ __ | |_   \ \  /\  / /__| |__ | |__) |__  _ __| |_ 
 | |    / _ \ __/ __|  __| | '_ \ / __| '__| | | | '_ \| __|   \ \/  \/ / _ \ '_ \|  ___/ _ \| '__| __|
 | |___|  __/ |_\__ \ |____| | | | (__| |  | |_| | |_) | |_     \  /\  /  __/ |_) | |  | (_) | |  | |_ 
 |______\___|\__|___/______|_| |_|\___|_|   \__, | .__/ \__|     \/  \/ \___|_.__/|_|   \___/|_|   \__|
                                             __/ | |                                                   
                                            |___/|_|                                                   
'@

Write-Host $banner -ForegroundColor Magenta

[string]$script:SqliteDllPath  = "$WebPortProgPath\System.Data.SQLite.dll"
[string]$script:WebPortDbPath  = "$WebPortDataPath\db\webport.sqlite"

$ErrorActionPreference = "Stop"

function step($t){ Write-Host "==> $t" -ForegroundColor Cyan }
function ok  ($t){ Write-Host "   ✓ $t" -ForegroundColor Green }
function warn($t){ Write-Host "   ⚠ $t" -ForegroundColor Yellow }
function err ($t){ Write-Host "   ✖ $t" -ForegroundColor Red }

function Read-WebPortSettings {
    if (!(Test-Path $SqliteDllPath)) { throw "SQLite DLL saknas: $SqliteDllPath" }
    if (!(Test-Path $WebPortDbPath)) { throw "DB saknas: $WebPortDbPath" }

    Add-Type -Path $SqliteDllPath

    $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$WebPortDbPath;")
    $conn.Open()

    $data = @{}

    try {
        # Läs DeviceGuid
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT DeviceGuid FROM settings LIMIT 1"
        $data.DeviceGuid = $cmd.ExecuteScalar()

        if (!$data.DeviceGuid) {
            throw "Ingen DeviceGuid hittades i databasen."
        }

        # Läs Key/Value-par
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT Key,Value FROM settings"
        $r = $cmd.ExecuteReader()
        while ($r.Read()) {
            $key = $r.GetString(0)
            $val = $r.GetString(1)
            $data[$key] = $val
        }
        $r.Close()
    }
    finally {
        $conn.Close()
    }

    return $data
}

function Get-WebPortServerPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$WebPortDataPath
    )

    $confPath = Join-Path $WebPortDataPath "webport.conf"

    if (-not (Test-Path $confPath)) {
        throw "webport.conf saknas: $confPath"
    }

    try {
        $confRaw = Get-Content $confPath -Raw -ErrorAction Stop
        $conf    = $confRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Kunde inte läsa eller parsa webport.conf → $($_.Exception.Message)"
    }

    if (-not $conf.default -or -not $conf.default.ServerPort) {
        throw "ServerPort saknas i webport.conf"
    }

    return [int]$conf.default.ServerPort
}

function Set-WebPortServerPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$WebPortDataPath,

        [Parameter(Mandatory=$true)]
        [int]$ServerPort
    )

    $confPath = Join-Path $WebPortDataPath "webport.conf"

    if (-not (Test-Path $confPath)) {
        throw "webport.conf saknas: $confPath"
    }

    try {
        $confRaw = Get-Content $confPath -Raw -ErrorAction Stop
        $conf    = $confRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Kunde inte läsa eller parsa webport.conf → $($_.Exception.Message)"
    }

    if (-not $conf.default) {
        throw "Ogiltig konfig: 'default' saknas i webport.conf"
    }

    # Sätt ny port
    $conf.default.ServerPort = $ServerPort

    # Skriv tillbaka
    $conf | ConvertTo-Json -Depth 10 | Set-Content -Path $confPath -Encoding UTF8

    return $ServerPort
}

function Set-WebPortServerPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$WebPortDataPath,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1,65535)]
        [int]$ServerPort
    )

    Write-Host "==> Uppdaterar WebPort ServerPort…" -ForegroundColor Cyan

    $confPath = Join-Path $WebPortDataPath "webport.conf"

    if (-not (Test-Path $confPath)) {
        Write-Host "⚠ webport.conf saknas – skapar ny standardfil" -ForegroundColor Yellow
        
        $defaultConf = @{
            default = @{
                ServerPort = $ServerPort
            }
        }

        try {
            $defaultConf | ConvertTo-Json -Depth 5 | Set-Content -Path $confPath -Encoding UTF8
            Write-Host "✓ webport.conf skapad med ServerPort=$ServerPort" -ForegroundColor Green
        }
        catch {
            throw "Kunde inte skriva webport.conf → $($_.Exception.Message)"
        }

        return $ServerPort
    }

    try {
        $confRaw = Get-Content $confPath -Raw -ErrorAction Stop
    }
    catch {
        throw "Kunde inte läsa webport.conf → $($_.Exception.Message)"
    }

    try {
        $conf = $confRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "⚠ webport.conf är korrupt JSON – återställer minimal struktur" -ForegroundColor Yellow

        $conf = @{
            default = @{
                ServerPort = $ServerPort
            }
        }
    }

    # Säkerställ sektionen "default"
    if (-not $conf.default) {
        $conf | Add-Member -MemberType NoteProperty -Name "default" -Value @{ ServerPort = $ServerPort }
    }

    # Uppdatera port
    $conf.default.ServerPort = $ServerPort

    try {
        $conf | ConvertTo-Json -Depth 10 |
            Set-Content -Path $confPath -Encoding UTF8

        Write-Host "✓ WebPort ServerPort uppdaterad → $ServerPort" -ForegroundColor Green
    }
    catch {
        throw "Kunde inte skriva uppdaterad webport.conf → $($_.Exception.Message)"
    }

    return $ServerPort
}

function Normalize-Pem {
    param([string]$pem)

    if ([string]::IsNullOrWhiteSpace($pem)) {
        return ""
    }

    $lines = $pem.Trim() -split "\r?\n"
    $lines = $lines | Where-Object { $_.Trim() -ne "" }
    return ($lines -join "`n")
}

function Test-OpenSSL {
    $cmd = Get-Command "openssl" -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return $cmd.Source
    }

    $commonPaths = @(
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
        "C:\OpenSSL-Win64\bin\openssl.exe",
        "C:\OpenSSL-Win32\bin\openssl.exe"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}

function Upsert-WebPortSetting {
    param(
        [System.Data.SQLite.SQLiteConnection]$Conn,
        [string]$Key,
        [string]$Value,
        [string]$DeviceGuid
    )

    $cmd = $Conn.CreateCommand()
    $cmd.CommandText = "SELECT COUNT(*) FROM settings WHERE Key=@k"
    $cmd.Parameters.AddWithValue("@k",$Key) | Out-Null
    $exists = $cmd.ExecuteScalar()

    if ($exists -gt 0) {
        $cmd = $Conn.CreateCommand()
        $cmd.CommandText = "UPDATE settings SET Value=@v WHERE Key=@k"
        $cmd.Parameters.AddWithValue("@k",$Key) | Out-Null
        $cmd.Parameters.AddWithValue("@v",$Value) | Out-Null
        $cmd.ExecuteNonQuery() | Out-Null
    }
    else {
        $cmd = $Conn.CreateCommand()
        $cmd.CommandText = "INSERT INTO settings (Key,Value,DeviceGuid) VALUES (@k,@v,@dg)"
        $cmd.Parameters.AddWithValue("@k",$Key) | Out-Null
        $cmd.Parameters.AddWithValue("@v",$Value) | Out-Null
        $cmd.Parameters.AddWithValue("@dg",$DeviceGuid) | Out-Null
        $cmd.ExecuteNonQuery() | Out-Null
    }
}

function Update-WebPortCertChain {
    param(
        [string]$LeafPem,
        [string]$IntermediatePem,
        [string]$RootPem,
        [string]$DeviceGuid
    )

    $LeafNorm = Normalize-Pem $LeafPem
    $InterNorm = Normalize-Pem $IntermediatePem
    $RootNorm = Normalize-Pem $RootPem

    Add-Type -Path $SqliteDllPath 

    $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$WebPortDbPath;")
    $conn.Open()

    try {
        Upsert-WebPortSetting -Conn $conn -Key "SSLCAPC" -Value $LeafNorm -DeviceGuid $DeviceGuid
        Upsert-WebPortSetting -Conn $conn -Key "SSLCAIC" -Value $InterNorm -DeviceGuid $DeviceGuid
        Upsert-WebPortSetting -Conn $conn -Key "SSLCARC" -Value $RootNorm -DeviceGuid $DeviceGuid
    }
    finally {
        $conn.Close()
    }

    ok "WebPort DB uppdaterad med cert chain"
}

function Reset-WebPortSSL {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "   ⚠ Failsafe – rensar SSL-relaterade fält i WebPort DB…" -ForegroundColor Yellow

    if (!(Test-Path $SqliteDllPath)) { throw "saknar SQLite DLL: $SqliteDllPath" }
    if (!(Test-Path $WebPortDbPath)) { throw "saknar DB: $WebPortDbPath" }

    Add-Type -Path $SqliteDllPath

    $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$WebPortDbPath;")
    $conn.Open()

    try {
        # Läs DeviceGuid
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT DeviceGuid FROM settings LIMIT 1"
        $dg = $cmd.ExecuteScalar()

        if ([string]::IsNullOrWhiteSpace($dg)) {
            Write-Warning "Ingen DeviceGuid hittades – fortsätter ändå."
            $dg = ""
        }

        function ClearKey([string]$key) {
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "SELECT COUNT(*) FROM settings WHERE Key=@k"
            $cmd.Parameters.AddWithValue("@k",$key) | Out-Null
            $exists = $cmd.ExecuteScalar()

            if ($exists -gt 0) {
                # UPDATE
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "UPDATE settings SET Value='' WHERE Key=@k"
                $cmd.Parameters.AddWithValue("@k",$key) | Out-Null
                $cmd.ExecuteNonQuery() | Out-Null
                Write-Host "  Rensade $key"
            }
            else {
                # INSERT tomt värde
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "INSERT INTO settings (Key,Value,DeviceGuid) VALUES (@k,'',@dg)"
                $cmd.Parameters.AddWithValue("@k",$key) | Out-Null
                $cmd.Parameters.AddWithValue("@dg",$dg) | Out-Null
                $cmd.ExecuteNonQuery() | Out-Null
                Write-Host "  $key saknades → skapad tom"
            }
        }

        ClearKey "SSLCSR"
        ClearKey "SSLPPK"
        ClearKey "SSLCAPC"
        ClearKey "SSLCAIC"
        ClearKey "SSLCARC"
        ClearKey "SSLCP"

    }
    finally {
        $conn.Close()
    }

    Write-Host ""
    Write-Host "   ✓ SSL-data har rensats från WebPort DB." -ForegroundColor Green
    Write-Host ""
}

function Restart-WebPort {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "   🔄 Återstartar WebPort…" -ForegroundColor Cyan

    # Konstant sökväg enligt installation
    $webPortExe  = "$WebPortProgPath\WebPortServer.exe"
    $serviceName = "WebPortServer"
    $processName = "WebPortServer.exe"

    $wasService = $false
    $procBefore = $false

    # ============================
    # Stoppa service
    # ============================
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "   ⏸ Stoppar service: $serviceName"
        Stop-Service $serviceName -Force
        $wasService = $true
    }

    # ============================
    # Stoppa EXE om ingen service stoppades
    # ============================
    #if (-not $wasService) {
        $p = Get-Process -Name ($processName -replace ".exe","") -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host "   ⏸ Stoppar process: $processName"
            Stop-Process -Id $p.Id -Force
            $procBefore = $true
        }
    #}

    Start-Sleep -Seconds 2

    if ($wasService) {
        Write-Host "   ▶ Startar service: $serviceName"
        Start-Service $serviceName
        Write-Host "   ▶ Startar process: $webPortExe"
        Start-Process $webPortExe
    }
    elseif ($procBefore) {
        Write-Host "   ▶ Startar process: $webPortExe"
        Start-Process $webPortExe
    }
    else {
        Write-Host "   ℹ WebPort var inte igång tidigare → startas ej"
    }

    Write-Host "   ✓ WebPort omstart klar." -ForegroundColor Green
    Write-Host ""
}

function Read-PluginArgsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "PluginArgs-fil hittades inte: $Path"
    }

    $raw = Get-Content -Path $Path -Raw

    # 1) JSON-format
    try {
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
        Write-Host "   ✓ PluginArgs importerad från JSON → $Path" -ForegroundColor Green
        return $json
    }
    catch {
        Write-Host "   ℹ Ej JSON → försöker tolka radvis Key=Value" -ForegroundColor Yellow
    }

    # 2) INI-liknande format "Key=Value"
    $args = @{}

    $lines = $raw -split "`r?`n"
    foreach ($ln in $lines) {
        if ($ln -match "^\s*#") { continue }
        if ($ln.Trim() -eq "") { continue }

        $kv = $ln -split "=",2
        if ($kv.Count -ne 2) { continue }

        $key = $kv[0].Trim()
        $val = $kv[1].Trim()

        # Försök auto-typning
        if ($val -match "^\d+$")       { $val = [int]$val }
        elseif ($val -match "^(true|false)$") { $val = [bool]$val }

        $args[$key] = $val
    }

    if ($args.Count -gt 0) {
        Write-Host "   ✓ PluginArgs importerad som Key=Value-format → $Path" -ForegroundColor Green
        return $args
    }

    throw "Kunde inte tolka PluginArgs från: $Path"
}

function Ensure-WebPortFirewallRule {
    param(
        [int]$ServerPort
    )

    if (-not $ServerPort) {
        throw "ServerPort är ej angiven"
    }

    $ruleName = "WebPort TCP $ServerPort"

    # Finns redan?
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "   ✓ Brandväggsregel finns redan: $ruleName" -ForegroundColor Green
        return
    }

    Write-Host "   ➕ Skapar brandväggsregel för inkommande TCP $ServerPort…" -ForegroundColor Cyan

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Enabled True `
        -Protocol TCP `
        -LocalPort $ServerPort `
        -Profile Any `
        | Out-Null

    Write-Host "   ✓ Brandväggsregel skapad: $ruleName" -ForegroundColor Green
}

function Ensure-PoshAcme {
    [CmdletBinding()]
    param()

    Write-Host "   🔍 Kontrollerar Posh-ACME…" -ForegroundColor Cyan

    # Finns modulen redan installerad?
    $mod = Get-Module -Name Posh-ACME -ListAvailable -ErrorAction SilentlyContinue

    if (-not $mod) {
        Write-Host "   ⚠ Posh-ACME saknas → installerar…" -ForegroundColor Yellow

        try {
            Install-Module Posh-ACME -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            Write-Host "   ✓ Posh-ACME installerad" -ForegroundColor Green
        }
        catch {
            Write-Host "   ❌ Kunde inte installera Posh-ACME:" -ForegroundColor Red
            Write-Host $_.Exception.Message
            throw
        }
    }
    else {
        Write-Host "   ✓ Posh-ACME är installerad" -ForegroundColor Green
    }

    # Importera
    try {
        Import-Module Posh-ACME -ErrorAction Stop
        Write-Host "   ✓ Modul importerad" -ForegroundColor Green
    }
    catch {
        Write-Host "   ❌ Kunde inte importera Posh-ACME" -ForegroundColor Red
        throw
    }
}

function Send-WebPortMail {
    param(
        [Parameter(Mandatory=$true)] [string]$To,
        [Parameter(Mandatory=$true)] [string]$Subject,
        [Parameter(Mandatory=$true)] [string]$Body
    )

    $Settings = Read-WebPortSettings

    $smtpServer    = $Settings["smtpserver"]
    $smtpPort      = [int]$Settings["smtpport"]
    $smtpSsl       = [bool]$Settings["smtpssl"]
    $smtpEncoding  = $Settings["smtpencoding"]
    $smtpFrom      = $Settings["smtpfrom"]
    $smtpUser      = $Settings["smtpuser"]

    if (-not $smtpServer) { throw "SMTP server saknas i WebPort DB." }
    if (-not $smtpFrom)   { throw "SMTP avsändaradress saknas i WebPort DB." }

    try {
        $SmtpPwd = ConvertTo-SecureString -String 'vH0z1oix73VfSaLs' -AsPlainText -Force
    }
    catch {
        throw "Kunde inte dekryptera SMTP-lösenordet (smtppassword) i databasen."
    }

    $credential = New-Object System.Management.Automation.PSCredential($smtpUser, $SmtpPwd)
    Write-Host "smtpUser: $smtpUser to: $To subject: $Subject server: $smtpServer port: $smtpPort ssl: $smtpSsl from: $smtpFrom"
    # Mail message
    $msg = New-Object System.Net.Mail.MailMessage
    $msg.From = $smtpFrom
    $msg.To.Add($To)
    $msg.Subject = $Subject
    $msg.Body = $Body

    try {
        if ($smtpEncoding) {
            $msg.BodyEncoding = [System.Text.Encoding]::GetEncoding($smtpEncoding)
        }
        else {
            $msg.BodyEncoding = [System.Text.Encoding]::UTF8
        }
    }
    catch {
        Write-Warning "Kunde inte använda encoding '$smtpEncoding'. Använder UTF-8."
        $msg.BodyEncoding = [System.Text.Encoding]::UTF8
    }

    # SMTP client
    $smtp = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
    $smtp.EnableSsl = $smtpSsl
    $smtp.Credentials = $credential
    $smtp.Timeout = 15000   # 15 sek timeout

    try {
        $smtp.Send($msg)
        Write-Host "✓ Mail skickat till $To" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✖ Misslyckades att skicka mail:" -ForegroundColor Red
        Write-Host "  Fel: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Host "  Inner: $($_.Exception.InnerException.Message)"
        }
        return $false
    }
}

function Add-Log {
    param(
        [string]$Text,
        [ValidateSet("Information","Warning","Error")]
        [string]$Level = "Information"
    )

    # 1) Intern logg (StringBuilder)
    $IssueCertLog.AppendLine("[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Level : $Text") | Out-Null

    # 2) EventLog Setup
    $logName = "Application"
    $source  = "WebPort-LetsEncrypt"

    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        try {
            New-EventLog -LogName $logName -Source $source
        }
        catch {
            # Om scriptet körs utan admin första gången kan detta misslyckas
            # Vi loggar då bara internt
            $IssueCertLog.AppendLine("WARNING: EventLog source could not be created: $($_.Exception.Message)") | Out-Null
            return
        }
    }

    # 3) Mappa Level till EventLog-type
    switch ($Level) {
        "Information" { $entryType = [System.Diagnostics.EventLogEntryType]::Information }
        "Warning"     { $entryType = [System.Diagnostics.EventLogEntryType]::Warning }
        "Error"       { $entryType = [System.Diagnostics.EventLogEntryType]::Error }
    }

    # 4) Skriv loggpost
    try {
        Write-EventLog -LogName $logName -Source $source -EntryType $entryType -EventId 1000 -Message $Text
    }
    catch {
        $IssueCertLog.AppendLine("ERROR: Failed to write to EventLog: $($_.Exception.Message)") | Out-Null
    }
}

$ScriptRoot = Split-Path -Parent $PSCommandPath
$SecurePasswordPath = Join-Path $ScriptRoot "securePassword.xml"


$IssueCertLog = New-Object System.Text.StringBuilder
$UseSecretStore = $true
if ($UseSecretStore -and !$failsafe) {

    Write-Host "==> SecretStore" -ForegroundColor Cyan

    # Säkerställ modul
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore)) {
        Write-Host "   ⚠ SecretStore modul saknas → installerar…" -ForegroundColor Yellow
        Install-Module Microsoft.PowerShell.SecretStore -Force -Scope AllUsers
    }

    Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
    Write-Host "   ✓ SecretStore laddad" -ForegroundColor Green

    # Kontrollera om SecretStore är initierad
    $storeInfo = Get-SecretStoreConfiguration -ErrorAction SilentlyContinue

    if (-not $storeInfo) {
        Write-Host "   ⚠ SecretStore inte initierad → initierar…" -ForegroundColor Yellow

        Set-SecretStoreConfiguration `
            -Scope AllUsers `
            -Authentication Password `
            -Confirm:$false

        Initialize-SecretStore `
            -Password (Read-Host "Ange nytt SecretStore-lösenord" -AsSecureString)

        Write-Host "   ✓ SecretStore initierad" -ForegroundColor Green
    }

    # Kontrollera lösenordsfil
    if (-not (Test-Path $SecurePasswordPath)) {
        Write-Host "   ⚠ securePasswordPath saknas → skapar..." -ForegroundColor Yellow

        $pwd = Read-Host "Ange SecretStore-lösenord för export" -AsSecureString
        $pwd | Export-CliXml -Path $SecurePasswordPath

        Write-Host "   ✓ Lösenord exporterat till $SecurePasswordPath" -ForegroundColor Green
    }

    # Lås upp SecretStore
    $password = Import-CliXml -Path $SecurePasswordPath
    Unlock-SecretStore -Password $password -ErrorAction Stop
    Write-Host "   ✓ SecretStore upplåst" -ForegroundColor Green

    try {
        $PluginArgs = Get-Secret -Name "PluginArgs" -AsPlainText
        Write-Host "   ✓ PluginArgs lästa från SecretStore" -ForegroundColor Green
    }
    catch {
Write-Host @"
Secret 'PluginArgs' saknas i SecretStore.

Du måste skapa PluginArgs baserat på DNS-pluginet du använder.
Följ plugin-guiden för ditt DNS-system:
    https://poshac.me/docs/v4/Plugins/

För Azure (certifikatbaserad autentisering – rekommenderad modell):
-------------------------------------------------------------
$($([char]36))pArgs = @{
    AZSubscriptionId   = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    AZAccessToken      = 'ey.........'
    AZResourceGroup    = 'Resourcegroup name'
    AZZoneName         = 'example.com'
}

Spara PluginArgs i SecretStore:
-------------------------------------------------------------
Set-Secret -Name PluginArgs -Secret `$pArgs

Kontrollera plugin-guiden för andra leverantörer och deras nödvändiga fält.

När PluginArgs är korrekt inlagda i SecretStore, kör scriptet igen.
"@
          throw "Secret 'PluginArgs' saknas i SecretStore. Skapa och lägg till enligt instruktioner ovan."        
    }

    try {
        $PfxPass = Get-Secret -Name "PfxPass" -AsPlainText
        Write-Host "   ✓ PfxPass läst från SecretStore" -ForegroundColor Green
    }
    catch {
        throw "Secret 'PfxPass' saknas i SecretStore. Lägg till med: Set-Secret -Name PfxPass -Secret 'hemligt'"
    }

    try {
        $SmtpPwd = Get-Secret -Name "SmtpPwd" -AsPlainText
        Write-Host "   ✓ SmtpPwd läst från SecretStore" -ForegroundColor Green
    }
    catch {
        throw "Secret 'SmtpPwd' saknas i SecretStore. Lägg till med: Set-Secret -Name SmtpPwd -Secret 'hemligt'"
    }
}

# Kontroll: PowerShell version
$minPS = [Version]"7.0.0"
if ($PSVersionTable.PSVersion -lt $minPS) {
    Write-Host "   ❌ Detta script kräver PowerShell $minPS eller senare." -ForegroundColor Red
    Write-Host "   Du kör: $($PSVersionTable.PSVersion)"
    Write-Host "   Installera senaste PowerShell här:"
    Write-Host "   https://learn.microsoft.com/powershell/scripting/install/installing-powershell"
    throw "PowerShell version för låg"
}
Write-Host "   ✓ PowerShell version OK: $($PSVersionTable.PSVersion)" -ForegroundColor Green

# Kontroll: Adminrättigheter
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "   ❌ Scriptet måste köras som administratör." -ForegroundColor Red
    Write-Host "   "
    Write-Host "   Högerklicka → 'Run as Administrator'"
    throw "Ej administratör"
}
Write-Host "   ✓ Administratörsrättigheter OK" -ForegroundColor Green

if ($ServerPort -ne (Get-WebPortServerPort -WebPortDataPath $WebPortDataPath)) {
    step "Sätter WebPort ServerPort till $ServerPort"
    Write-Host "   ✓ Sätter WebPort ServerPort till $ServerPort" -ForegroundColor Green
    $newPort = Set-WebPortServerPort -WebPortDataPath $WebPortDataPath -ServerPort $ServerPort
    Ensure-WebPortFirewallRule -ServerPort $newPort
    Restart-WebPort
    Write-Host "`n✓ WebPort cleanup klar" -ForegroundColor Green
    ok "WebPort ServerPort satt till $newPort"
}

if (!$failsafe) {
    step "Säkerställer att PoshAcme är installerad"
    Ensure-PoshAcme
    Import-Module Posh-ACME -ErrorAction Stop | Out-Null
    ok "PoshAcme är installerad"

    step "Läser WebPort DB"
    $Settings   = Read-WebPortSettings
    $SSLCN      = $Settings["SSLCN"]
    $SSLCSR     = $Settings["SSLCSR"]
    $DeviceGuid = $Settings["DeviceGuid"]
    $SSLCP      = $Settings["SSLCP"]


    if ([string]::IsNullOrWhiteSpace($SSLCP)) {
        Write-Host "   ✖ Inget Cert-lösenord hittad i WebPort-databasen." -ForegroundColor Red
    }
        
    if ([string]::IsNullOrWhiteSpace($SSLCSR)) {
        Write-Host "   ✖ Ingen CSR (SSLCSR) hittad i WebPort-databasen." -ForegroundColor Red
    }

    if ([string]::IsNullOrWhiteSpace($SSLCSR) -or [string]::IsNullOrWhiteSpace($SSLCP)) {
        Write-Host ""
        Write-Host "För att fortsätta måste du skapa en CSR i WebPorts GUI:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   1) Logga in i WebPort"
        Write-Host "   2) Gå till: Systeminställningar → Server → SSL Certifikat"
        Write-Host "   3) Ange:"
        Write-Host "        • Common Name (CN) = fullt domännamn"
        Write-Host "        • SAN (Alternative Names) om fler namn behövs"
        Write-Host "        • Lösenord"
        Write-Host "   4) Klicka: Spara"
        Write-Host "   5) Gå tillbaka:  SSL Certifikat"
        Write-Host "   6) Klicka: Create CSR"
        Write-Host ""
        Write-Host "CSR kommer därefter att lagras automatiskt i databasen (settings → SSLCSR)."
        Write-Host ""
        Write-Host "Kör sedan skriptet igen."
        Write-Host ""

        Write-Error "CSR saknas — skapa via WebPort GUI innan du fortsätter."
    }

    if (!$SSLCSR) { throw "Ingen CSR (SSLCSR) hittad i WebPort DB. Skapa via GUI först." }

    # Domain = CN = första entry i SSLCN
    $CN = $SSLCN -split ";" | Select-Object -First 1
    Write-Host "   CN = $CN" -ForegroundColor Green

    # Skriv CSR till fil
    $csrFile = Join-Path $env:TEMP "wp.csr"
    Set-Content $csrFile $SSLCSR -Encoding ascii
    ok "CSR skriven till $csrFile"
    
    step "Läser WebPort conf-file $WebPortDataPath\webport.conf"

    if (!(Test-Path "$WebPortDataPath\webport.conf")) {
        throw "webport.conf saknas: $confPath"
    }

    $conf = Get-Content "$WebPortDataPath\webport.conf" -Raw | ConvertFrom-Json
    $ServerPort = $conf.default.ServerPort
    Write-Host "   ServerPort = $ServerPort" -ForegroundColor Green
    Ensure-WebPortFirewallRule -ServerPort $ServerPort
    ok "webport.conf läst"
}

if ($failsafe){
    $Settings   = Read-WebPortSettings

    Reset-WebPortSSL
    Set-WebPortServerPort -WebPortDataPath $WebPortDataPath -ServerPort 8090

    if (Test-Path "$WebPortDataPath\webport.p12") {
        Write-Host "Tar bort P12 → $WebPortDataPath\webport.p12"
        Remove-Item "$WebPortDataPath\webport.p12" -Force
    }
    else {
        Write-Host "Ingen P12 hittad → hoppar över"
    }

    # RENSAR CERT I KEYSTORE
    $SSLCN = $Settings["SSLCN"]

    if ($SSLCN) {
        Write-Host "   SSLCN=$SSLCN"

        # CN kan innehålla ";SAN..." → ta första
        $CN = ($SSLCN -split ";")[0]

        Write-Host "   Rensar cert i certstore för CN=$CN"

        $items = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Subject -eq "CN=$CN" }

        foreach ($c in $items) {
            Write-Host "Tar bort cert: $($c.Thumbprint)"
            Remove-Item "Cert:\LocalMachine\My\$($c.Thumbprint)" -Force
        }
    }
    else {
        Write-Warning "SSLCN saknas i DB → hoppar över keystore-rensning"
    }
    Restart-WebPort
    Write-Host "   ✓ WebPort cleanup klar" -ForegroundColor Green

}

if ($CreateScheduledTask) {

    step "Skapar schemalagd uppgift för automatisering"

    # Hitta PowerShell 7
    $pwsh = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue
    if (-not $pwsh) {
        throw "PowerShell 7 (pwsh.exe) not found. Install from: https://learn.microsoft.com/powershell/"
    }

    # Scriptets fulla sökväg
    $ScriptPath = $PSCommandPath

    # Lista för uppbyggning av argument
    $argsList = @()

    # === FIXA obligatoriska parametrar ===
    $argsList += "-IssueCert"
    $argsList += "-InstallPfx"

    # === Dynamiska parametrar hämtas från scriptets körning ===

    # Strängparametrar
    if ($DnsPlugin)       { $argsList += "-DnsPlugin `"$DnsPlugin`"" }
    if ($WebPortDataPath) { $argsList += "-WebPortDataPath `"$WebPortDataPath`"" }
    if ($WebPortProgPath) { $argsList += "-WebPortProgPath `"$WebPortProgPath`"" }
    if ($Sendmail)        { $argsList += "-Sendmail `"$Sendmail`"" }

    # Bygg argumentsträngen för scheduled task
    $finalArgs = "-NoLogo -NoProfile -File `"$ScriptPath`" $($argsList -join ' ')"

    Write-Host "   Kommandorad för scheduled task:"
    Write-Host "   pwsh.exe $finalArgs" -ForegroundColor Yellow

    # Scheduled Task action
    $action = New-ScheduledTaskAction -Execute $pwsh.Source -Argument $argumentString
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00am
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
    ok "Schemalagd uppgift '$taskName' skapad. Körs varje söndag kl 02:00 via PowerShell 7."
    # wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /e:true
    return
}


if ($IssueCert) {

    step "Startar IssueCert-process"
    Add-Log "Startar IssueCert-process"

    $Settings = Read-WebPortSettings
    $SSLCN = $Settings["SSLCN"]

    try {
        if ($DnsPlugin -eq "Azure") {
            Add-Log "DnsPlugin = Azure"

            $ctx = Get-AzContext
            if (-not $ctx) { Add-Log "Get-AzContext returnerade null"; throw "Ingen Azure-context" }

            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token | ConvertFrom-SecureString -AsPlainText

            Add-Log "Azure-token genererad"

            $PluginArgs = @{
                AZSubscriptionId = $ctx.Subscription.Id
                AZAccessToken    = $token
                AZResourceGroup  = $ResourceGroup
                AZZoneName       = $ZoneName
            }

            Add-Log "PluginArgs: **********"
        }
        elseif ($PluginArgsFile) {

            step "Läser PluginArgs från fil"
            Add-Log "Läser PluginArgsFile: $PluginArgsFile"

            $PluginArgs = Read-PluginArgsFile -Path $PluginArgsFile

            Add-Log "PluginArgs lästa: **********"
            ok "PluginArgs lästa"
        }
        else {
            $PluginArgs = Get-Secret -Name PluginArgs -AsPlainText | ConvertTo-Json
            $PfxPass = Get-Secret -Name PfxPass    -AsPlainText
            $SmtpPwd = Get-Secret -Name SmtpPwd    -AsPlainText
        }
            Add-Log "Cert finns: $($cert.Thumbprint), giltigt till: $($cert.NotAfter), dagar kvar: $daysLeft"

        if (($PluginArgs) -and ($PfxPass) -and ($SmtpPwd)) {

            $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "CN=$SSLCN" }
            $daysLeft = ($cert.NotAfter - (Get-Date)).Days
            
            if ($daysLeft -lt 30 -or -not $cert) { 

                Add-Log "Förnyar cert via ACME (CSR mode)"
                pause
                New-PACertificate `
                    -CSR $csrFile `
                    -DnsPlugin $DnsPlugin `
                    -PluginArgs $PluginArgs `
                    -Verbose

                Add-Log "New-PACertificate körd OK"

                Add-Log "Kör Complete-PAOrder"
                Complete-PAOrder

                Add-Log "Complete-PAOrder klar"

                $pa = Get-PACertificate
                if (!$pa) {
                    Add-Log "ERROR: Get-PACertificate gav tomt resultat"
                    Add-Log "Sannolik orsak: felaktiga DNS-plugin parametrar"

                    write-host "Get-PACertificate → tomt resultat (Förmodligen fel i DNS-plugin parameter)"
                    write-host "$($PluginArgs|ConvertTo-Json)"
                }
                else {
                    Add-Log "Get-PACertificate OK: $($pa.Thumbprint)"
                    Add-Log "Certificate giltigt till: $($pa.NotAfter)"
                
                }

                # Full chain
                Add-Log "Läser FullChainFile från $($pa.FullChainFile)"
                $full = Get-Content $pa.FullChainFile -Raw

                Add-Log "Delar upp cert-kedjan"
                $certs = $full -split "-----END CERTIFICATE-----"
                $certs = $certs | ForEach-Object { ($_ + "-----END CERTIFICATE-----") } |
                Where-Object { $_ -match "BEGIN CERTIFICATE" }

                $leaf = if ($certs.Count -ge 1) { Add-Log "Leaf cert OK"; $certs[0] } else { Add-Log "Leaf saknas"; "" }
                $inter = if ($certs.Count -ge 2) { Add-Log "Intermediate cert OK"; $certs[1] } else { Add-Log "Intermediate saknas"; "" }

                # Root PEM
                $rootUrl = "https://letsencrypt.org/certs/isrgrootx1.pem.txt"
                Add-Log "Hämtar Root PEM från $rootUrl"
                $rootPem = Invoke-WebRequest -Uri $rootUrl -UseBasicParsing | Select-Object -ExpandProperty Content
                Add-Log "Root PEM hämtad"

                Update-WebPortCertChain -LeafPem $leaf -IntermediatePem $inter -RootPem $rootPem -DeviceGuid $DeviceGuid
                Add-Log "WebPort-databasen uppdaterad med cert chain"
            }
            else {
                Add-Log "Cert finns: $($cert.Thumbprint), giltigt till: $($cert.NotAfter), dagar kvar: $daysLeft" -Level Information
                Write-Host "   ✓ Cert finns och är giltigt i $daysLeft dagar → ingen förnyelse behövs" -ForegroundColor Green
                break
            }
            
        }
        else {
            Write-Warning "Ett eller flera secrets saknas. Avbryter steg."
        }


    }
    catch {
        Add-Log "FEL: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Add-Log "INNER: $($_.Exception.InnerException.Message)"
        }
        throw  # bibehåll samma felbeteende
    }
    finally {
        Add-Log "IssueCert-process avslutad"
    }

}

if ($InstallPfx) {

    Add-Log "Startar InstallPfx-process"
    step "Bygger webport.p12"
    Add-Log "Initierar byggandet av webport.p12"

    try {

        $openssl = Test-OpenSSL
        if (-not $openssl) {
            Add-Log "FEL: OpenSSL saknas"
            throw "OpenSSL saknas – installera först! https://slproweb.com/products/Win32OpenSSL.html"
        }

        Add-Log "OpenSSL hittades: $openssl"

        $tmp = $env:TEMP
        $pfxTemp = Join-Path $tmp "webport_temp.pfx"
        Add-Log "Temporär PFX-sökväg: $pfxTemp"

        # Paths för pem-material
        $privKeyPath = Join-Path $tmp "privkey.pem"
        $certPath    = Join-Path $tmp "cert.pem"
        $chainPath   = Join-Path $tmp "chain.pem"

        Add-Log "PEM paths:"
        Add-Log "  privKeyPath = $privKeyPath"
        Add-Log "  certPath    = $certPath"
        Add-Log "  chainPath   = $chainPath"

        $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Subject -eq "CN=$CN" }

        if ($cert) {

            Add-Log "Cert hittades i LocalMachine\My för CN=$CN"
            Write-Host "   ✓ Cert hittades i LocalMachine\My → exporterar" -ForegroundColor Green

            Add-Log "Exporterar PFX från certstore"
            $pfxBytes = $cert.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
                $PfxPass
            )

            [System.IO.File]::WriteAllBytes($pfxTemp, $pfxBytes)
            Add-Log "Temporär PFX exporterad till $pfxTemp"

            Add-Log "Extraherar cert och key från PFX via OpenSSL"

            & $openssl pkcs12 -in  $pfxTemp -nodes -nokeys  -out $certPath    -password pass:$PfxPass
            Add-Log "Extraherat cert → $certPath"

            & $openssl pkcs12 -in  $pfxTemp -nodes -nocerts -out $privKeyPath -password pass:$PfxPass
            Add-Log "Extraherat privat nyckel → $privKeyPath"

            & $openssl pkcs12 -in  $pfxTemp -nodes -nokeys  -out $chainPath   -password pass:$PfxPass
            Add-Log "Extraherat chain.pem → $chainPath"
        }
        else {

            Add-Log "Cert saknas i LocalMachine\My → hämtar certdata från WebPort DB"
            Write-Host "   ⚠ Cert saknas i LocalMachine\My → hämtar material från DB"

            $Settings   = Read-WebPortSettings
            $SSLPPK  = $Settings["SSLPPK"]
            $SSLCAPC = $Settings["SSLCAPC"]
            $SSLCAIC = $Settings["SSLCAIC"]
            $SSLCARC = $Settings["SSLCARC"]

            Add-Log "DB-values:"
            Add-Log "  SSLPPK present: $([bool]$SSLPPK)"
            Add-Log "  SSLCAPC present: $([bool]$SSLCAPC)"
            Add-Log "  SSLCAIC present: $([bool]$SSLCAIC)"
            Add-Log "  SSLCARC present: $([bool]$SSLCARC)"

            if (-not $SSLPPK) {
                Add-Log "FEL: Ingen privat nyckel hittad i DB"
                throw "Ingen privat nyckel hittad i DB (SSLPPK)"
            }
            if (-not $SSLCAPC) {
                Add-Log "FEL: SSLCAPC saknas i DB"
                throw "SSLCAPC (leaf cert) saknas i DB"
            }

            Add-Log "Skriver PEM-filer från DB-innehåll"
            Set-Content -Path $privKeyPath -Value $SSLPPK   -Encoding ascii
            Set-Content -Path $certPath    -Value $SSLCAPC  -Encoding ascii

            # Bygg chain.pem
            $chainPem = ""

            if ($SSLCAIC) { 
                $chainPem += $SSLCAIC + "`n"
                Add-Log "Intermediate cert tillagd"
            }
            if ($SSLCARC) { 
                $chainPem += $SSLCARC + "`n"
                Add-Log "Root cert tillagd"
            }

            if ($chainPem -ne "") {
                Set-Content -Path $chainPath -Value $chainPem -Encoding ascii
                Add-Log "chain.pem skapad"
            }
            else {
                Write-Warning "   Ingen intermediate/root certkedja hittad i DB"
                Add-Log "Ingen intermediate/root certkedja hittad, skapar tom chain.pem"
                Set-Content -Path $chainPath -Value "" -Encoding ascii
            }
        }

        Add-Log "Kör OpenSSL export → webport.p12"

        & $openssl pkcs12 -export `
            -inkey    $privKeyPath `
            -in       $certPath `
            -certfile $chainPath `
            -out      "$WebPortDataPath\webport.p12" `
            -password pass:$PfxPass

        Add-Log "webport.p12 skapad → $WebPortDataPath\webport.p12"
        ok "P12 skapad → $WebPortDataPath\webport.p12"
        step "Installerar cert i LocalMachine\My"
        Add-Log "Installerar certifikat i LocalMachine\My"
        certutil -f -p $script:PfxPass -ImportPfx "$WebPortDataPath\webport.p12"
        Add-Log "certutil ImportPfx slutförd"
        Restart-WebPort
        Add-Log "WebPort restartad efter cert-installation"
        ok "Cert installerat"
        Add-Log "InstallPfx-process avslutad OK"

    }
    catch {
        Add-Log "FEL i InstallPfx: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Add-Log "INNER: $($_.Exception.InnerException.Message)"
        }
        throw
    }

}

if ($Sendmail){
    step "Analysera och skicka log vid fel"
    $Settings = Read-WebPortSettings
    $SSLCN    = $Settings["SSLCN"]
    $DoSendMail = ($($IssueCertLog.ToString()) -match '(?i)(exception|error|fail|failed|timeout|denied|missing|not found|unable|could not|invalid)') 

    if ($DoSendMail) {
        step "Skickar mail till $Sendmail"
        Add-Log "Problem upptäckta i loggen → skickar mail"
        err "Problem upptäckta i loggen → skickar mail"
        $global:IssueCertLog = $IssueCertLog 
        Send-WebPortMail -To $Sendmail -Subject "$SSLCN - Problem med att förnya certifikat" -Body $IssueCertLog.ToString()
        OK "Mail skickat till $Sendmail"
    }
    else {
        Add-Log "Inga problem upptäckta i loggen → mail skickas"
        Send-WebPortMail -To $Sendmail -Subject "$SSLCN - Förnyat certifikat" -Body $IssueCertLog.ToString()
        ok "Inga problem upptäckta i loggen → mail skickas"
    }
}

Write-Host "`n✓ KLART" -ForegroundColor Green
