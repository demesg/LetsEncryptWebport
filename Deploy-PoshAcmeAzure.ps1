<#
.SYNOPSIS
Configures Azure DNS plugin prerequisites for Posh-ACME by creating or updating a certificate-based service principal with least-privilege TXT record access.

.DESCRIPTION
This script prepares Azure DNS access for Posh-ACME without requesting an ACME certificate.
It signs in to Azure with device code authentication by default, finds the Azure DNS zone,
creates or updates the custom 'DNS TXT Contributor' role if needed, creates or reuses a local
machine certificate used only as the service principal authentication credential, creates or updates
the Azure service principal, assigns the role on the DNS resource group, and exports plugin arguments
to a JSON file.

The local machine certificate is not the public web/server certificate for the site. It is used by
Posh-ACME to sign in as the service principal and update Azure DNS TXT records for DNS-01 validation.

On successful setup, the script prepares $global:pArgs for the current PowerShell session and writes
the same plugin arguments to the JSON config file. LetsEncryptWebport.ps1 does not read this global
variable directly; save it to SecretStore with Set-Secret -Name PluginArgs -Secret $pArgs before
running LetsEncryptWebport.ps1.
The signed-in account does not need to be Global Administrator, but it must have enough Azure RBAC
and Microsoft Entra permissions to create/update custom roles, create/update the service principal,
and assign the role. With -Uninstall, the script removes the matching service principal and local
authentication certificate(s).

.EXAMPLE
.\Deploy-PoshAcmeAzure.ps1 -Domain MyAzureDomain.com
Creates or updates Azure DNS plugin prerequisites and writes plugin config to the default JSON path.

.EXAMPLE
.\Deploy-PoshAcmeAzure.ps1 -Domain MyAzureDomain.com
Set-Secret -Name PluginArgs -Secret $pArgs
Creates Azure DNS plugin prerequisites, prepares $global:pArgs, and saves the plugin arguments to SecretStore for LetsEncryptWebport.ps1.
.EXAMPLE
.\Deploy-PoshAcmeAzure.ps1 -Domain MyAzureDomain.com -ServicePrincipalDisplayName PoshACME-SRV01 -Uninstall
Removes matching Azure service principal(s) and local authentication certificate(s) for the specified domain/display name.
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

function Write-Info {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
}

function Disconnect-AzureSession {
    Write-Step 'Disconnecting from Azure'
    Write-Info 'Signing out of the Az PowerShell session used by this script.'
    Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
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
        Write-Info "The module is missing or older than $MinimumVersion. It will be installed for the current user."

        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Info 'NuGet package provider is required for PSGallery installs and will be installed if missing.'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        }

        $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
            Write-Info 'PSGallery will be trusted so the required module can be installed without extra prompts.'
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
    else {
        Write-Info "Module '$Name' is already available with version $($available.Version)."
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
    Write-Info "Module '$Name' is loaded."
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
    throw 'This script targets Windows because it writes the service principal authentication certificate to Cert:\LocalMachine\My.'
}

if (-not (Test-IsAdministrator)) {
    throw 'Run this script in an elevated PowerShell session (Run as Administrator).'
}

Write-Step 'Loading required modules'
Write-Info 'The script loads Azure PowerShell modules and, unless uninstalling, Posh-ACME and Azure DNS support.'
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
    Write-Info "Verifying that the '$PoshAcmePlugin' Posh-ACME plugin and Azure DNS cmdlets are available."
    if (-not (Get-Command -Name 'Get-AzDnsZone' -ErrorAction SilentlyContinue)) {
        throw "Cmdlet 'Get-AzDnsZone' is unavailable. Install/update Az.Dns: Install-Module Az.Dns -Scope CurrentUser -Force"
    }

    $azurePlugin = @(Get-PAPlugin | Where-Object { $_.Name -eq $PoshAcmePlugin })
    if ($azurePlugin.Count -eq 0) {
        throw "Posh-ACME plugin '$PoshAcmePlugin' is not available in this module installation."
    }
}

Write-Step 'Connecting to Azure'
Write-Info 'If no existing Az context is available, device code login will be used.'
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Info 'Follow the device code instructions shown by Azure PowerShell to complete login.'
    Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext
}
else {
    Write-Info "Reusing existing Azure context for account '$($ctx.Account.Id)'."
}

if (-not $ctx) {
    throw 'Could not read Azure context after login.'
}

$subscriptionId = $ctx.Subscription.Id
$tenantId = $ctx.Subscription.TenantId
Write-Step "Using subscription: $subscriptionId"
Write-Info "Tenant: $tenantId"
Write-Info 'All Azure DNS role and service principal work will be done in this subscription context.'

$spCertSubject = "CN=$ServicePrincipalDisplayName.$Domain"

if ($Uninstall) {
    Write-Step "Uninstall mode enabled"
    Write-Info 'This removes the matching service principal and local authentication certificate only. It does not delete the DNS zone, DNS records, or web/server certificates.'

    Write-Step "Removing Azure service principal(s) named '$ServicePrincipalDisplayName'"
    Write-Info 'The script searches by exact display name and removes matching Microsoft Entra service principal objects.'
    $matchingSps = @(
        Get-AzADServicePrincipal -DisplayName $ServicePrincipalDisplayName -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $ServicePrincipalDisplayName }
    )

    $removedSpCount = 0
    foreach ($matchingSp in $matchingSps) {
        Write-Info "Removing service principal object $($matchingSp.Id)."
        Remove-AzADServicePrincipal -ObjectId $matchingSp.Id -Confirm:$false -ErrorAction Stop | Out-Null
        $removedSpCount++
    }
    if ($removedSpCount -eq 0) {
        Write-Info 'No matching service principal was found.'
    }

    Write-Step "Removing local machine authentication certificate(s) with subject '$spCertSubject'"
    Write-Info 'The script removes matching service principal authentication certificates from Cert:\LocalMachine\My on this computer.'
    $matchingCerts = @(
        Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
            Where-Object { $_.Subject -eq $spCertSubject }
    )

    $removedCertCount = 0
    foreach ($matchingCert in $matchingCerts) {
        Write-Info "Removing authentication certificate $($matchingCert.Thumbprint)."
        Remove-Item -Path ("Cert:\LocalMachine\My\{0}" -f $matchingCert.Thumbprint) -Force -ErrorAction Stop
        $removedCertCount++
    }
    if ($removedCertCount -eq 0) {
        Write-Info 'No matching local authentication certificate was found.'
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
    Disconnect-AzureSession
    return
}

Write-Step "Looking up Azure DNS zone '$Domain'"
Write-Info 'The DNS zone must already exist in the current subscription.'
$zones = @(Get-AzDnsZone -ErrorAction Stop | Where-Object { $_.Name -eq $Domain })
if ($zones.Count -eq 0) {
    throw "No Azure DNS zone named '$Domain' was found in the current subscription."
}

if (-not $ResourceGroupName) {
    Write-Info 'No resource group was provided, so the script will infer it from the matching DNS zone.'
    if ($zones.Count -gt 1) {
        $zoneGroups = $zones.ResourceGroupName -join ', '
        throw "Multiple Azure DNS zones named '$Domain' found ($zoneGroups). Provide -ResourceGroupName explicitly."
    }

    $ResourceGroupName = $zones[0].ResourceGroupName
    Write-Info "Resolved DNS zone resource group to '$ResourceGroupName'."
}

$zoneInGroup = @($zones | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName })
if ($zoneInGroup.Count -eq 0) {
    throw "Azure DNS zone '$Domain' was not found in resource group '$ResourceGroupName'."
}

Write-Step "Using resource group: $ResourceGroupName"
Write-Info 'The service principal will receive TXT record permissions on this resource group scope.'

$roleName = 'DNS TXT Contributor'
$subscriptionScope = "/subscriptions/$subscriptionId"

Write-Step "Ensuring custom role '$roleName'"
Write-Info "The role allows TXT record management, DNS zone read access, and required read/diagnostic operations."
$role = Get-AzRoleDefinition -Name $roleName -ErrorAction SilentlyContinue
if (-not $role) {
    Write-Info "Custom role '$roleName' was not found and will be created at subscription scope."
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
    Write-Info "Custom role exists, but subscription scope is missing. Updating assignable scopes."
    $role.AssignableScopes = @($role.AssignableScopes + $subscriptionScope | Select-Object -Unique)
    $role = Set-AzRoleDefinition -Role $role
}
else {
    Write-Info "Custom role '$roleName' already exists and is assignable in this subscription."
}

$now = Get-Date
$notBefore = $now
$notAfter = $now.AddYears($CredentialYears)
Write-Step 'Ensuring local machine authentication certificate for service principal'
Write-Info "Looking for a reusable service principal authentication certificate with subject '$spCertSubject' and at least 30 days remaining."
Write-Info 'This certificate is used to authenticate to Azure and update DNS TXT records. It is not the public web/server certificate.'
$cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' |
    Where-Object {
        $_.Subject -eq $spCertSubject -and
        $_.NotAfter -gt (Get-Date).AddDays(30)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

$createdNewCert = $false
if (-not $cert) {
    Write-Info "No reusable authentication certificate was found. Creating a self-signed certificate valid for $CredentialYears year(s)."
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
else {
    Write-Info "Reusing authentication certificate $($cert.Thumbprint), valid until $($cert.NotAfter)."
}

$certData = [Convert]::ToBase64String($cert.GetRawCertData())

Write-Step "Ensuring service principal '$ServicePrincipalDisplayName'"
Write-Info 'The service principal is the non-interactive identity that Posh-ACME will use later.'
$sp = @(Get-AzADServicePrincipal -DisplayName $ServicePrincipalDisplayName -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($sp.Count -eq 0) {
    Write-Info 'No existing service principal was found. Creating it and binding the authentication certificate credential.'
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
    Write-Info "Reusing service principal AppId $($sp.AppId). Checking whether the authentication certificate is already bound."
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
        Write-Info 'Adding the current authentication certificate as a credential on the service principal.'
        New-AzADSpCredential -ObjectId $sp.Id -CertValue $certData -StartDate $cert.NotBefore -EndDate $cert.NotAfter | Out-Null
    }
    else {
        Write-Info 'The current authentication certificate is already bound to the service principal.'
    }
}

Write-Step 'Ensuring role assignment on Azure DNS resource group'
$scope = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName"
Write-Info "Checking whether AppId $($sp.AppId) already has '$roleName' on $scope."
$existingAssignment = Get-AzRoleAssignment -ApplicationId $sp.AppId -Scope $scope -RoleDefinitionName $roleName -ErrorAction SilentlyContinue
if (-not $existingAssignment) {
    Write-Info 'Role assignment is missing. Creating it; Azure propagation can require retries.'
    $maxRetries = 12
    $assigned = $false

    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            Write-Info "Role assignment attempt $i of $maxRetries."
            New-AzRoleAssignment -ApplicationId $sp.AppId -ResourceGroupName $ResourceGroupName -RoleDefinitionName $roleName -ErrorAction Stop | Out-Null
            $assigned = $true
            break
        }
        catch {
            if ($i -eq $maxRetries) {
                throw
            }
            Write-Info 'Azure has not propagated the service principal yet. Waiting 10 seconds before retrying.'
            Start-Sleep -Seconds 10
        }
    }

    if (-not $assigned) {
        throw 'Failed to create role assignment for service principal.'
    }
}
else {
    Write-Info 'Role assignment already exists.'
}

Write-Step 'Building Azure plugin configuration (no ACME order is created)'
Write-Info "Writing subscription, tenant, AppId, and authentication certificate thumbprint to '$resolvedConfigPath'."
$pluginArgs = [ordered]@{
    AZSubscriptionId = $subscriptionId
    AZTenantId = $tenantId
    AZAppUsername = $sp.AppId
    AZCertThumbprint = $cert.Thumbprint
}

$global:pArgs = @{}
foreach ($pluginArg in $pluginArgs.GetEnumerator()) {
    $global:pArgs[$pluginArg.Key] = $pluginArg.Value
}
Write-Info 'Global $pArgs has been prepared for the current PowerShell session.'
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
Write-Host "Global `$pArgs is ready in this PowerShell session. To recreate it from ${resolvedConfigPath}:" -ForegroundColor Gray
Write-Host "`$pArgs = @{}; (Get-Content '$escapedConfigPath' -Raw | ConvertFrom-Json).PluginArgs.PSObject.Properties | ForEach-Object { `$pArgs[`$_.Name] = `$_.Value }" -ForegroundColor Blue
Write-Host " Remove '$escapedConfigPath' when done" -ForegroundColor yellow

Disconnect-AzureSession
