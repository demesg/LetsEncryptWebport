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
  • Installs certificate into LocalMachine\My (performed in ExportPfx step)
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
  • Only ExportPfx installs the certificate into certstore

PARAMETERS
  -failsafe
      Resets SSL data without ACME. Must NOT be combined with PfxPass.

  -IssueCert
      Requests/renews certificate via ACME using the existing CSR.

  -ExportPfx
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
PS> .\LetsEncryptWebport.ps1 -IssueCert -ExportPfx -PfxPass "secret"

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
    [Parameter(ParameterSetName="Normal", Mandatory=$true)]
    [string]$PfxPass,
    [Parameter(ParameterSetName="FailSafe", Mandatory=$true)]
    [switch]$failsafe,
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [switch]$IssueCert,
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [switch]$ExportPfx,
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [string]$ZoneName ,
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [string]$ResourceGroup ,
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [string]$script:WebPortDataPath = "C:\ProgramData\WebPort",
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [string]$script:WebPortProgPath = "C:\Program Files\WebPort",
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [string]$DnsPlugin ,
    [Parameter(ParameterSetName="Normal")]
    [Parameter(ParameterSetName="FailSafe")]
    [string]$PluginArgsFile
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

# Om Normal-set används, lägg PfxPass i script-scope
if ($PSCmdlet.ParameterSetName -eq "Normal") {
    $script:PfxPass = $PfxPass
}


[string]$script:SqliteDllPath  = "$WebPortProgPath\System.Data.SQLite.dll"
[string]$script:WebPortDbPath  = "$WebPortDataPath\db\webport.sqlite"
$script:PfxPass  = $PfxPass 

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
function Set-WebPortServerPort {
    [CmdletBinding()]
    param(
        [string]$WebPortDataPath,
        [int]$ServerPort
    )

    $confPath = Join-Path $WebPortDataPath "webport.conf"

    if (-not (Test-Path $confPath)) {
        Write-Host "⚠ webport.conf saknas – skapar ny standardfil" -ForegroundColor Yellow
        
        $defaultConf = @{
            default = @{
                ServerPort = $ServerPort
            }
        }

        $defaultConf | ConvertTo-Json -Depth 5 | 
            Set-Content -Path $confPath -Encoding UTF8

        Write-Host "✅ webport.conf skapad"
        return $ServerPort
    }

    $confRaw = Get-Content $confPath -Raw -ErrorAction Stop
    $conf    = $confRaw | ConvertFrom-Json -ErrorAction Stop

    if (-not $conf.default) {
        $conf | Add-Member -MemberType NoteProperty -Name "default" -Value @{ ServerPort = $ServerPort }
    }

    if ($ServerPort) {
        $conf.default.ServerPort = $ServerPort
    }

    $conf | ConvertTo-Json -Depth 10 |
        Set-Content -Path $confPath -Encoding UTF8

    Write-Host "✅ WebPort ServerPort uppdaterad → $($conf.default.ServerPort)" -ForegroundColor Green

    return $conf.default.ServerPort
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
    Write-Host "   ✅ SSL-data har rensats från WebPort DB." -ForegroundColor Green
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

    Write-Host "   ✅ WebPort omstart klar." -ForegroundColor Green
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
        Write-Host "   ✅ PluginArgs importerad från JSON → $Path" -ForegroundColor Green
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
        Write-Host "   ✅ PluginArgs importerad som Key=Value-format → $Path" -ForegroundColor Green
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
        Write-Host "   ✅ Brandväggsregel finns redan: $ruleName" -ForegroundColor Green
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

    Write-Host "   ✅ Brandväggsregel skapad: $ruleName" -ForegroundColor Green
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
            Write-Host "   ✅ Posh-ACME installerad" -ForegroundColor Green
        }
        catch {
            Write-Host "   ❌ Kunde inte installera Posh-ACME:" -ForegroundColor Red
            Write-Host $_.Exception.Message
            throw
        }
    }
    else {
        Write-Host "   ✅ Posh-ACME är installerad" -ForegroundColor Green
    }

    # Importera
    try {
        Import-Module Posh-ACME -ErrorAction Stop
        Write-Host "   ✅ Modul importerad" -ForegroundColor Green
    }
    catch {
        Write-Host "   ❌ Kunde inte importera Posh-ACME" -ForegroundColor Red
        throw
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
Write-Host "   ✅ PowerShell version OK: $($PSVersionTable.PSVersion)" -ForegroundColor Green

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

Write-Host "   ✅ Administratörsrättigheter OK" -ForegroundColor Green
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

if ($IssueCert) {
    step "Förnyar cert via ACME (CSR mode)"

    if ($DnsPlugin -eq "Azure") {
        # Auto-populate Azure
        $ctx = Get-AzContext
        $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token | ConvertFrom-SecureString -AsPlainText

        $PluginArgs = @{
            AZSubscriptionId = $ctx.Subscription.Id
            AZAccessToken    = $token
            AZResourceGroup  = $ResourceGroup
            AZZoneName       = $ZoneName
        }
    } elseif ($PluginArgsFile) {
        step "Läser PluginArgs från fil"
        $PluginArgs = Read-PluginArgsFile -Path $PluginArgsFile
        ok "PluginArgs lästa"
    }
    else {
        throw "Ingen PluginArgsFile angiven!"
    }

    New-PACertificate `
        -CSR $csrFile `
        -DnsPlugin $DnsPlugin `
        -PluginArgs $PluginArgs `
        -Verbose
    Complete-PAOrder

    $pa = Get-PACertificate
    if (!$pa) { 
        write-host "Get-PACertificate → tomt resultat (Förmodligen fel i DNS-plugin parameter)"
        write-host "$($PluginArgs|ConvertTo-Json)"  
    }

    # Full chain
    $full = Get-Content $pa.FullChainFile -Raw

    # Dela upp kedjan
    $certs = $full -split "-----END CERTIFICATE-----"
    $certs = $certs | ForEach-Object { ($_ + "-----END CERTIFICATE-----") } |
        Where-Object { $_ -match "BEGIN CERTIFICATE" }

    $leaf  = if ($certs.Count -ge 1) { $certs[0] } else { "" }
    $inter = if ($certs.Count -ge 2) { $certs[1] } else { "" }

    # Hämta root PEM
    $rootUrl = "https://letsencrypt.org/certs/isrgrootx1.pem.txt"
    $rootPem = Invoke-WebRequest -Uri $rootUrl -UseBasicParsing | Select-Object -ExpandProperty Content

    Update-WebPortCertChain -LeafPem $leaf -IntermediatePem $inter -RootPem $rootPem -DeviceGuid $DeviceGuid 
}

if ($ExportPfx) {

    step "Bygger webport.p12"

    $openssl = Test-OpenSSL
    if (-not $openssl) {
        throw "OpenSSL saknas – installera först! https://slproweb.com/products/Win32OpenSSL.html"
    }

    $tmp = $env:TEMP
    $pfxTemp = Join-Path $tmp "webport_temp.pfx"

    # Paths för pem-material
    $privKeyPath = Join-Path $tmp "privkey.pem"
    $certPath    = Join-Path $tmp "cert.pem"
    $chainPath   = Join-Path $tmp "chain.pem"

    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=$CN" }

    if ($cert) {

        Write-Host "✅ Cert hittades i LocalMachine\My → exporterar"
        
        $pfxBytes = $cert.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            $PfxPass
        )

        [System.IO.File]::WriteAllBytes($pfxTemp, $pfxBytes)

        # Extrahera key + cert från PFX
        & $openssl pkcs12 -in  $pfxTemp -nodes -nokeys  -out $certPath    -password pass:$PfxPass
        & $openssl pkcs12 -in  $pfxTemp -nodes -nocerts -out $privKeyPath -password pass:$PfxPass
        & $openssl pkcs12 -in  $pfxTemp -nodes -nokeys  -out $chainPath   -password pass:$PfxPass
    }
    else {

        Write-Host "⚠ Cert saknas i LocalMachine\My → hämtar material från DB"

        # ============================
        # 2) Läs cert/nyckel från DB
        # ============================
        $Settings   = Read-WebPortSettings
        $SSLPPK  = $Settings["SSLPPK"]
        $SSLCAPC = $Settings["SSLCAPC"]
        $SSLCAIC = $Settings["SSLCAIC"]
        $SSLCARC = $Settings["SSLCARC"]

        if (-not $SSLPPK) {
            throw "Ingen privat nyckel hittad i DB (SSLPPK)"
        }
        if (-not $SSLCAPC) {
            throw "SSLCAPC (leaf cert) saknas i DB"
        }

        # Skriv PEM-material till fil
        Set-Content -Path $privKeyPath -Value $SSLPPK   -Encoding ascii
        Set-Content -Path $certPath    -Value $SSLCAPC  -Encoding ascii

        # Bygg chain.pem
        $chainPem = ""

        if ($SSLCAIC) { $chainPem += $SSLCAIC + "`n" }
        if ($SSLCARC) { $chainPem += $SSLCARC + "`n" }

        if ($chainPem -ne "") {
            Set-Content -Path $chainPath -Value $chainPem -Encoding ascii
        }
        else {
            Write-Warning "Ingen intermediate/root certkedja hittad i DB"
            # Skapa tom fil för openssl
            Set-Content -Path $chainPath -Value "" -Encoding ascii
        }
    }

    & $openssl pkcs12 -export `
        -inkey    $privKeyPath `
        -in       $certPath `
        -certfile $chainPath `
        -out      "$WebPortDataPath\webport.p12"`
        -password pass:$PfxPass

    ok "P12 skapad → $WebPortDataPath\webport.p12"


    step "Installerar cert i LocalMachine\My"
    certutil -f -p $script:PfxPass -ImportPfx "$WebPortDataPath\webport.p12"
    Restart-WebPort
    ok "Cert installerat"
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
        Write-Host "SSLCN=$SSLCN"

        # CN kan innehålla ";SAN..." → ta första
        $CN = ($SSLCN -split ";")[0]

        Write-Host "Rensar cert i certstore för CN=$CN"

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

    Write-Host "`n✅ WebPort cleanup klar" -ForegroundColor Green

}

Write-Host "`n✅ KLART" -ForegroundColor Green
