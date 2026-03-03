<#
.SYNOPSIS
Configures Azure DNS plugin prerequisites for Posh-ACME by creating or updating a certificate-based service principal.

.DESCRIPTION
This script prepares Azure DNS access for Posh-ACME without requesting an ACME certificate.
It can create or update a custom role, local machine certificate, and Azure service principal,
then export plugin arguments to a JSON file. With -Uninstall, it removes the matching service principal
and local certificate(s).

.EXAMPLE
.\Deploy-PoshAcmeAzure.ps1 -Domain MyAzureDomain.com
Creates or updates Azure DNS plugin prerequisites and writes plugin config to the default JSON path.

.EXAMPLE
.\Deploy-PoshAcmeAzure.ps1 -Domain MyAzureDomain.com -ServicePrincipalDisplayName PoshACME-SRV01 -Uninstall
Removes matching Azure service principal(s) and local certificate(s) for the specified domain/display name.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,
    [string]$ServicePrincipalDisplayName = "PoshACME-$env:COMPUTERNAME",
    [string]$ResourceGroupName,
    [int]$CredentialYears = 5,
    [string]$PluginConfigPath = '.\PoshAcme-AzureDns-PluginConfig.json',
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DnsProvider = 'Azure DNS'
$PoshAcmePlugin = 'Azure'
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$resolvedConfigPath = if ([System.IO.Path]::IsPathRooted($PluginConfigPath)) {
    [System.IO.Path]::GetFullPath($PluginConfigPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path -Path $scriptRoot -ChildPath $PluginConfigPath))
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Ensure-Module {
    param(
        [Parameter(Mandatory)][string]$Name,
        [version]$MinimumVersion = '0.0.0'
    )

    $available = Get-Module -ListAvailable -Name $Name |
        Sort-Object Version -Descending |
        Select-Object -First 1

    $needsInstall = (-not $available) -or ($available.Version -lt $MinimumVersion)
    if ($needsInstall) {
        Write-Step "Installing module '$Name' from PSGallery"

        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        }

        $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }

        $installParams = @{
            Name = $Name
            Scope = 'CurrentUser'
            Force = $true
            AllowClobber = $true
            ErrorAction = 'Stop'
            Confirm = $false
        }

        if ($MinimumVersion -gt [version]'0.0.0') {
            $installParams.MinimumVersion = $MinimumVersion
        }

        Install-Module @installParams | Out-Null
    }

    $importParams = @{
        Name = $Name
        Force = $true
        ErrorAction = 'Stop'
    }

    if ($MinimumVersion -gt [version]'0.0.0') {
        $importParams.MinimumVersion = $MinimumVersion
    }

    Import-Module @importParams | Out-Null
}

function Get-HexStringFromBytes {
    param([byte[]]$Bytes)
    (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This script targets Windows because it writes certificates to Cert:\LocalMachine\My.'
}

if (-not (Test-IsAdministrator)) {
    throw 'Run this script in an elevated PowerShell session (Run as Administrator).'
}

Write-Step 'Loading required modules'
$requiredModules = @(
    @{ Name = 'Az.Accounts'; MinimumVersion = [version]'5.0.0' },
    @{ Name = 'Az.Resources'; MinimumVersion = [version]'8.0.0' }
)

if (-not $Uninstall) {
    $requiredModules += @(
        @{ Name = 'Az.Dns'; MinimumVersion = [version]'1.3.0' },
        @{ Name = 'Posh-ACME'; MinimumVersion = [version]'4.0.0' }
    )
}

foreach ($module in $requiredModules) {
    Ensure-Module -Name $module.Name -MinimumVersion $module.MinimumVersion
}

if (-not $Uninstall) {
    if (-not (Get-Command -Name 'Get-AzDnsZone' -ErrorAction SilentlyContinue)) {
        throw "Cmdlet 'Get-AzDnsZone' is unavailable. Install/update Az.Dns: Install-Module Az.Dns -Scope CurrentUser -Force"
    }

    $azurePlugin = @(Get-PAPlugin | Where-Object { $_.Name -eq $PoshAcmePlugin })
    if ($azurePlugin.Count -eq 0) {
        throw "Posh-ACME plugin '$PoshAcmePlugin' is not available in this module installation."
    }
}

Write-Step 'Connecting to Azure'
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext
}

if (-not $ctx) {
    throw 'Could not read Azure context after login.'
}

$subscriptionId = $ctx.Subscription.Id
$tenantId = $ctx.Subscription.TenantId
Write-Step "Using subscription: $subscriptionId"

$spCertSubject = "CN=$ServicePrincipalDisplayName.$Domain"

if ($Uninstall) {
    Write-Step "Uninstall mode enabled"

    Write-Step "Removing Azure service principal(s) named '$ServicePrincipalDisplayName'"
    $matchingSps = @(
        Get-AzADServicePrincipal -DisplayName $ServicePrincipalDisplayName -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $ServicePrincipalDisplayName }
    )

    $removedSpCount = 0
    foreach ($matchingSp in $matchingSps) {
        Remove-AzADServicePrincipal -ObjectId $matchingSp.Id -Confirm:$false -ErrorAction Stop | Out-Null
        $removedSpCount++
    }

    Write-Step "Removing local machine certificate(s) with subject '$spCertSubject'"
    $matchingCerts = @(
        Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
            Where-Object { $_.Subject -eq $spCertSubject }
    )

    $removedCertCount = 0
    foreach ($matchingCert in $matchingCerts) {
        Remove-Item -Path ("Cert:\LocalMachine\My\{0}" -f $matchingCert.Thumbprint) -Force -ErrorAction Stop
        $removedCertCount++
    }

    Write-Host ''
    Write-Host 'Done. Uninstall summary:' -ForegroundColor Green
    [pscustomobject]@{
        Mode = 'Uninstall'
        Domain = $Domain
        SubscriptionId = $subscriptionId
        ServicePrincipalDisplayName = $ServicePrincipalDisplayName
        ServicePrincipalsRemoved = $removedSpCount
        LocalCertificatesRemoved = $removedCertCount
        PluginConfigPath = $resolvedConfigPath
    }
    return
}

Write-Step "Looking up Azure DNS zone '$Domain'"
$zones = @(Get-AzDnsZone -ErrorAction Stop | Where-Object { $_.Name -eq $Domain })
if ($zones.Count -eq 0) {
    throw "No Azure DNS zone named '$Domain' was found in the current subscription."
}

if (-not $ResourceGroupName) {
    if ($zones.Count -gt 1) {
        $zoneGroups = $zones.ResourceGroupName -join ', '
        throw "Multiple Azure DNS zones named '$Domain' found ($zoneGroups). Provide -ResourceGroupName explicitly."
    }

    $ResourceGroupName = $zones[0].ResourceGroupName
}

$zoneInGroup = @($zones | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName })
if ($zoneInGroup.Count -eq 0) {
    throw "Azure DNS zone '$Domain' was not found in resource group '$ResourceGroupName'."
}

Write-Step "Using resource group: $ResourceGroupName"

$roleName = 'DNS TXT Contributor'
$subscriptionScope = "/subscriptions/$subscriptionId"

Write-Step "Ensuring custom role '$roleName'"
$role = Get-AzRoleDefinition -Name $roleName -ErrorAction SilentlyContinue
if (-not $role) {
    $roleDef = Get-AzRoleDefinition -Name 'DNS Zone Contributor'
    $roleDef.Id = $null
    $roleDef.Name = $roleName
    $roleDef.Description = 'Manage Azure DNS TXT records only.'
    $roleDef.Actions.RemoveRange(0, $roleDef.Actions.Count)
    $roleDef.Actions.Add('Microsoft.Network/dnsZones/TXT/*')
    $roleDef.Actions.Add('Microsoft.Network/dnsZones/read')
    $roleDef.Actions.Add('Microsoft.Authorization/*/read')
    $roleDef.Actions.Add('Microsoft.Insights/alertRules/*')
    $roleDef.Actions.Add('Microsoft.ResourceHealth/availabilityStatuses/read')
    $roleDef.Actions.Add('Microsoft.Resources/deployments/read')
    $roleDef.Actions.Add('Microsoft.Resources/subscriptions/resourceGroups/read')
    $roleDef.AssignableScopes.Clear()
    $roleDef.AssignableScopes.Add($subscriptionScope)

    $role = New-AzRoleDefinition $roleDef
}
elseif ($role.AssignableScopes -notcontains $subscriptionScope) {
    $role.AssignableScopes = @($role.AssignableScopes + $subscriptionScope | Select-Object -Unique)
    $role = Set-AzRoleDefinition -Role $role
}

$now = Get-Date
$notBefore = $now
$notAfter = $now.AddYears($CredentialYears)
Write-Step 'Ensuring local machine certificate for service principal'
$cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' |
    Where-Object {
        $_.Subject -eq $spCertSubject -and
        $_.NotAfter -gt (Get-Date).AddDays(30)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

$createdNewCert = $false
if (-not $cert) {
    $certParams = @{
        CertStoreLocation = 'Cert:\LocalMachine\My'
        Subject = $spCertSubject
        HashAlgorithm = 'SHA256'
        Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
        NotBefore = $notBefore
        NotAfter = $notAfter
    }

    $cert = New-SelfSignedCertificate @certParams
    $createdNewCert = $true
}

$certData = [Convert]::ToBase64String($cert.GetRawCertData())

Write-Step "Ensuring service principal '$ServicePrincipalDisplayName'"
$sp = @(Get-AzADServicePrincipal -DisplayName $ServicePrincipalDisplayName -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($sp.Count -eq 0) {
    $spParams = @{
        DisplayName = $ServicePrincipalDisplayName
        CertValue = $certData
        StartDate = $cert.NotBefore
        EndDate = $cert.NotAfter
    }
    $sp = New-AzADServicePrincipal @spParams
}
else {
    $sp = $sp[0]
    $spCreds = @(Get-AzADSpCredential -ObjectId $sp.Id -ErrorAction SilentlyContinue)
    $certThumbHex = Get-HexStringFromBytes -Bytes $cert.GetCertHash()
    $certAlreadyBound = $false

    foreach ($cred in $spCreds) {
        if (-not $cred.CustomKeyIdentifier) {
            continue
        }

        $credBytes = if ($cred.CustomKeyIdentifier -is [string]) {
            [Convert]::FromBase64String($cred.CustomKeyIdentifier)
        }
        else {
            [byte[]]$cred.CustomKeyIdentifier
        }

        if ((Get-HexStringFromBytes -Bytes $credBytes) -eq $certThumbHex) {
            $certAlreadyBound = $true
            break
        }
    }

    if ($createdNewCert -or -not $certAlreadyBound) {
        New-AzADSpCredential -ObjectId $sp.Id -CertValue $certData -StartDate $cert.NotBefore -EndDate $cert.NotAfter | Out-Null
    }
}

Write-Step 'Ensuring role assignment on Azure DNS resource group'
$scope = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName"
$existingAssignment = Get-AzRoleAssignment -ApplicationId $sp.AppId -Scope $scope -RoleDefinitionName $roleName -ErrorAction SilentlyContinue
if (-not $existingAssignment) {
    $maxRetries = 12
    $assigned = $false

    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            New-AzRoleAssignment -ApplicationId $sp.AppId -ResourceGroupName $ResourceGroupName -RoleDefinitionName $roleName -ErrorAction Stop | Out-Null
            $assigned = $true
            break
        }
        catch {
            if ($i -eq $maxRetries) {
                throw
            }
            Start-Sleep -Seconds 10
        }
    }

    if (-not $assigned) {
        throw 'Failed to create role assignment for service principal.'
    }
}

Write-Step 'Building Azure plugin configuration (no ACME order is created)'
$pluginArgs = [ordered]@{
    AZSubscriptionId = $subscriptionId
    AZTenantId = $tenantId
    AZAppUsername = $sp.AppId
    AZCertThumbprint = $cert.Thumbprint
}

$configObject = [ordered]@{
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    Domain = $Domain
    DnsProvider = $DnsProvider
    Plugin = $PoshAcmePlugin
    PluginArgs = $pluginArgs
}

($configObject | ConvertTo-Json -Depth 6) | Set-Content -Path $resolvedConfigPath -Encoding ASCII

Write-Host ''
Write-Host 'Done. Summary:' -ForegroundColor Green
[pscustomobject]@{
    Domain = $Domain
    DnsProvider = $DnsProvider
    ResourceGroupName = $ResourceGroupName
    SubscriptionId = $subscriptionId
    TenantId = $tenantId
    ServicePrincipalDisplayName = $ServicePrincipalDisplayName
    ServicePrincipalAppId = $sp.AppId
    ServicePrincipalCertThumbprint = $cert.Thumbprint
    RoleName = $roleName
    Plugin = $PoshAcmePlugin
    PluginConfigPath = $resolvedConfigPath
    AcmeCertificateRequested = $false
}

Write-Host ''
Write-Host 'Azure plugin args prepared for future Posh-ACME use.' -ForegroundColor Gray
$escapedConfigPath = $resolvedConfigPath -replace "'", "''"
Write-Host "Create `$pArgs from ${resolvedConfigPath}:" -ForegroundColor Gray
Write-Host "`$pArgs = @{}; (Get-Content '$escapedConfigPath' -Raw | ConvertFrom-Json).PluginArgs.PSObject.Properties | ForEach-Object { `$pArgs[`$_.Name] = `$_.Value }" -ForegroundColor Blue
Write-Host " Remove '$escapedConfigPath' when done" -ForegroundColor yellow
