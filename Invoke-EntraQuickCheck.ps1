<#
.SYNOPSIS
    Rychlá kontrola 6 základních bezpečnostních nastavení Microsoft Entra ID (jen čtení).

.DESCRIPTION
    Skript se připojí k Microsoft Graph s oprávněními pouze pro čtení a zkontroluje:
      1. Počet globálních administrátorů
      2. Vynucení MFA (Security Defaults nebo Conditional Access)
      3. Blokování legacy autentizace
      4. Souhlas uživatelů s aplikacemi třetích stran (user consent)
      5. Registrace aplikací běžnými uživateli
      6. Kdo smí zvát hosty (guest invite)

    Nic nemění. Potřebuje pouze modul Microsoft.Graph.Authentication.

.PARAMETER UseDeviceCode
    Přihlášení přes device code (obchází problémy s WAM brokerem ve Windows).

.PARAMETER ExportCsv
    Volitelná cesta k CSV souboru s výsledky.

.EXAMPLE
    ./Invoke-EntraQuickCheck.ps1

.EXAMPLE
    ./Invoke-EntraQuickCheck.ps1 -UseDeviceCode -ExportCsv ./vysledky.csv

.NOTES
    Autor:   Martin Pavlíček, Permetria (https://permetria.cz)
    Licence: MIT
    Kompletní audit (50 kontrolních bodů) nabízí Permetria jako službu.
#>
#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [switch]$UseDeviceCode,
    [string]$ExportCsv
)

$ErrorActionPreference = 'Stop'

$Scopes = @('Policy.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All')
$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

# --- Helpers -----------------------------------------------------------------

function Get-GraphAll {
    param([string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($resp.value) { $items.AddRange([object[]]$resp.value) }
        $Uri = $resp.'@odata.nextLink'
    }
    return $items
}

$Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [int]$Id,
        [string]$Check,
        [ValidateSet('OK', 'RIZIKO', 'VAROVANI', 'CHYBA')][string]$Status,
        [string]$Detail
    )
    $Results.Add([pscustomobject]@{
        Id     = $Id
        Kontrola = $Check
        Stav   = $Status
        Detail = $Detail
    })
}

# --- Connect -----------------------------------------------------------------

$connectParams = @{ Scopes = $Scopes; NoWelcome = $true }
if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }
Connect-MgGraph @connectParams

$ctx = Get-MgContext
Write-Host "`nTenant: $($ctx.TenantId)  |  Účet: $($ctx.Account)`n" -ForegroundColor Cyan

# --- 1. Global administrators -------------------------------------------------

try {
    $assignments = Get-GraphAll "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GlobalAdminRoleId'&`$expand=principal"
    $count = @($assignments).Count
    $names = ($assignments | ForEach-Object { $_.principal.userPrincipalName ?? $_.principal.displayName }) -join ', '
    $status = if ($count -lt 2) { 'RIZIKO' } elseif ($count -gt 4) { 'RIZIKO' } else { 'OK' }
    $detail = "Aktivních přiřazení: $count (doporučeno 2–4). $names"
    if ($count -lt 2) { $detail += ' — chybí záložní (break-glass) účet.' }
    Add-Result 1 'Počet globálních administrátorů' $status $detail
}
catch { Add-Result 1 'Počet globálních administrátorů' 'CHYBA' $_.Exception.Message }

# --- 2 + 3. MFA enforcement and legacy auth -----------------------------------

$secDefaults = $null
$caPolicies  = @()
try {
    $secDefaults = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -OutputType PSObject).isEnabled
}
catch {
    Add-Result 2 'Vynucení MFA' 'CHYBA' "Security Defaults: $($_.Exception.Message)"
    Add-Result 3 'Blokování legacy autentizace' 'CHYBA' "Security Defaults: $($_.Exception.Message)"
}

$caError = $null
try {
    $caPolicies = @(Get-GraphAll 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' |
        Where-Object state -eq 'enabled')
}
catch { $caError = $_.Exception.Message }

if ($null -ne $secDefaults -and -not $secDefaults -and $caError) {
    Add-Result 2 'Vynucení MFA' 'CHYBA' "Conditional Access nelze načíst: $caError"
    Add-Result 3 'Blokování legacy autentizace' 'CHYBA' "Conditional Access nelze načíst: $caError"
}
elseif ($null -ne $secDefaults) {
    $mfaPolicies = $caPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All' -and
        ($_.grantControls.builtInControls -contains 'mfa' -or $_.grantControls.authenticationStrength)
    }
    if ($secDefaults) {
        Add-Result 2 'Vynucení MFA' 'OK' 'Zapnuté Security Defaults.'
    }
    elseif ($mfaPolicies) {
        Add-Result 2 'Vynucení MFA' 'OK' "CA politika pro všechny uživatele: $(($mfaPolicies.displayName) -join ', ')"
    }
    else {
        Add-Result 2 'Vynucení MFA' 'RIZIKO' 'Security Defaults vypnuté a žádná zapnutá CA politika nevyžaduje MFA pro všechny uživatele.'
    }

    $legacyBlock = $caPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'block' -and
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or $_.conditions.clientAppTypes -contains 'other')
    }
    if ($secDefaults) {
        Add-Result 3 'Blokování legacy autentizace' 'OK' 'Blokováno přes Security Defaults.'
    }
    elseif ($legacyBlock) {
        Add-Result 3 'Blokování legacy autentizace' 'OK' "CA politika: $(($legacyBlock.displayName) -join ', ')"
    }
    else {
        Add-Result 3 'Blokování legacy autentizace' 'RIZIKO' 'Legacy protokoly (IMAP/POP/SMTP AUTH, ActiveSync) nejsou blokovány — obcházejí MFA.'
    }
}

# --- 4, 5, 6. Authorization policy --------------------------------------------

try {
    $authz = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType PSObject
    $consent = @($authz.permissionGrantPolicyIdsAssignedToDefaultUserRole) -join ','

    # 4. User consent
    if ($consent -match 'microsoft-user-default-legacy') {
        Add-Result 4 'Souhlas uživatelů s aplikacemi' 'RIZIKO' 'Uživatelé mohou udělit aplikacím třetích stran přístup k datům bez schválení admina.'
    }
    elseif ($consent -match 'microsoft-user-default-low') {
        Add-Result 4 'Souhlas uživatelů s aplikacemi' 'VAROVANI' 'Povolen souhlas jen pro ověřené vydavatele a nízkorizikové oprávnění. Zvažte admin consent workflow.'
    }
    elseif ($consent -match 'ManagePermissionGrantsForSelf') {
        Add-Result 4 'Souhlas uživatelů s aplikacemi' 'VAROVANI' "Vlastní politika souhlasu: $consent"
    }
    else {
        Add-Result 4 'Souhlas uživatelů s aplikacemi' 'OK' 'Uživatelé nemohou sami udělovat souhlas aplikacím.'
    }

    # 5. App registration
    if ($authz.defaultUserRolePermissions.allowedToCreateApps) {
        Add-Result 5 'Registrace aplikací uživateli' 'RIZIKO' 'Každý uživatel může registrovat aplikace v tenantu.'
    }
    else {
        Add-Result 5 'Registrace aplikací uživateli' 'OK' 'Registrace aplikací je omezena na administrátory.'
    }

    # 6. Guest invitations
    switch ($authz.allowInvitesFrom) {
        'everyone'                         { Add-Result 6 'Zvaní hostů' 'RIZIKO'   'Hosty může zvát kdokoli, včetně jiných hostů.' }
        'adminsGuestInvitersAndAllMembers' { Add-Result 6 'Zvaní hostů' 'VAROVANI' 'Hosty mohou zvát všichni členové organizace.' }
        default                            { Add-Result 6 'Zvaní hostů' 'OK'       "Omezeno: $($authz.allowInvitesFrom)" }
    }
}
catch {
    foreach ($i in 4..6) { Add-Result $i 'Authorization policy' 'CHYBA' $_.Exception.Message }
}

# --- Output -------------------------------------------------------------------

$colors = @{ OK = 'Green'; VAROVANI = 'Yellow'; RIZIKO = 'Red'; CHYBA = 'Magenta' }
foreach ($r in $Results | Sort-Object Id) {
    Write-Host ('[{0,-8}] ' -f $r.Stav) -ForegroundColor $colors[$r.Stav] -NoNewline
    Write-Host "$($r.Id). $($r.Kontrola)"
    Write-Host "           $($r.Detail)" -ForegroundColor DarkGray
}

$risks = @($Results | Where-Object Stav -eq 'RIZIKO').Count
Write-Host "`nNalezená rizika: $risks z $($Results.Count) kontrol." -ForegroundColor $(if ($risks) { 'Red' } else { 'Green' })
Write-Host 'Toto je jen 6 základních kontrol. Kompletní audit Entra ID (50 bodů): https://permetria.cz' -ForegroundColor Cyan

if ($ExportCsv) {
    $Results | Sort-Object Id | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
    Write-Host "Výsledky uloženy: $ExportCsv"
}

Disconnect-MgGraph | Out-Null
