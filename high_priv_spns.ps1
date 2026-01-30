 <#
.SYNOPSIS
    Finds Active Directory users with Service Principal Names (SPNs) who have high-privilege group membership.

.DESCRIPTION
    This script queries Active Directory for user accounts that have SPNs configured
    and checks if they are members of high-privilege groups (directly or through nested groups).
    Uses LDAP_MATCHING_RULE_IN_CHAIN for efficient recursive group membership checking.
    
    Users with SPNs and privileged access are high-value targets for Kerberoasting attacks.
    
    Groups checked:
    - Domain Admins
    - Enterprise Admins
    - Schema Admins
    - Administrators (Built-in)
    - Account Operators
    - Server Operators
    - Backup Operators
    - Print Operators
    - DnsAdmins
    - Group Policy Creator Owners
    - Key Admins
    - Enterprise Key Admins

.PARAMETER Server
    Specifies the domain controller to query. If not specified, uses the default DC.

.PARAMETER SearchBase
    Specifies the AD path to search. If not specified, searches the entire domain.

.PARAMETER ExportCsv
    If specified, exports results to the provided CSV file path.

.EXAMPLE
    .\Get-SPNPrivilegedUsers.ps1

.EXAMPLE
    .\Get-SPNPrivilegedUsers.ps1 -ExportCsv "C:\Reports\spn_privileged.csv"

.NOTES
    Requires: ActiveDirectory PowerShell module
    Author: Security Audit Script
    Version: 2.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Server,

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [string]$ExportCsv
)

#Requires -Version 5.0

function Test-ADModuleAvailable {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not installed. Please install RSAT tools."
        return $false
    }
    return $true
}

function Get-UsersWithSPN {
    param(
        [string]$Server,
        [string]$SearchBase
    )
    
    $params = @{
        Filter = {ServicePrincipalName -like "*"}
        Properties = @(
            'SamAccountName',
            'DisplayName',
            'DistinguishedName',
            'ServicePrincipalName',
            'Enabled',
            'PasswordLastSet',
            'LastLogonDate',
            'Description',
            'MemberOf',
            'AdminCount'
        )
    }
    
    if (-not [string]::IsNullOrEmpty($Server)) {
        $params['Server'] = $Server
    }
    
    if (-not [string]::IsNullOrEmpty($SearchBase)) {
        $params['SearchBase'] = $SearchBase
    }
    
    try {
        Get-ADUser @params
    }
    catch {
        Write-Error "Failed to query Active Directory: $_"
        return $null
    }
}

function Test-PrivilegedGroupMembership {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        
        [Parameter(Mandatory)]
        [hashtable]$PrivilegedGroups,
        
        [string]$Server
    )
    
    $memberships = [System.Collections.ArrayList]::new()
    
    foreach ($groupName in $PrivilegedGroups.Keys) {
        $groupDN = $PrivilegedGroups[$groupName]
        
        if ([string]::IsNullOrEmpty($groupDN)) {
            continue
        }
        
        # Check direct membership first
        $isDirect = $User.MemberOf -contains $groupDN
        
        if ($isDirect) {
            [void]$memberships.Add([PSCustomObject]@{
                GroupName = $groupName
                GroupDN = $groupDN
                MembershipType = "Direct"
            })
            continue
        }
        
        # Use LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) for recursive check
        $ldapFilter = "(memberOf:1.2.840.113556.1.4.1941:=$groupDN)"
        
        $params = @{
            LDAPFilter = $ldapFilter
            SearchBase = $User.DistinguishedName
            SearchScope = 'Base'
            ErrorAction = 'SilentlyContinue'
        }
        
        if (-not [string]::IsNullOrEmpty($Server)) {
            $params['Server'] = $Server
        }
        
        $nestedResult = Get-ADUser @params
        
        if ($nestedResult) {
            [void]$memberships.Add([PSCustomObject]@{
                GroupName = $groupName
                GroupDN = $groupDN
                MembershipType = "Nested"
            })
        }
    }
    
    return $memberships
}

function Get-PrivilegedGroupDNs {
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [string]$RootDomainDN,
        
        [string]$Server
    )
    
    $groups = @{}
    
    # Domain-level groups
    $domainGroups = @(
        @{ Name = "Domain Admins"; Path = "CN=Domain Admins,CN=Users,$DomainDN" }
        @{ Name = "Administrators"; Path = "CN=Administrators,CN=Builtin,$DomainDN" }
        @{ Name = "Account Operators"; Path = "CN=Account Operators,CN=Builtin,$DomainDN" }
        @{ Name = "Server Operators"; Path = "CN=Server Operators,CN=Builtin,$DomainDN" }
        @{ Name = "Backup Operators"; Path = "CN=Backup Operators,CN=Builtin,$DomainDN" }
        @{ Name = "Print Operators"; Path = "CN=Print Operators,CN=Builtin,$DomainDN" }
        @{ Name = "DnsAdmins"; Path = "CN=DnsAdmins,CN=Users,$DomainDN" }
        @{ Name = "Group Policy Creator Owners"; Path = "CN=Group Policy Creator Owners,CN=Users,$DomainDN" }
        @{ Name = "Key Admins"; Path = "CN=Key Admins,CN=Users,$DomainDN" }
    )
    
    # Forest root groups (only exist in root domain)
    $forestGroups = @(
        @{ Name = "Enterprise Admins"; Path = "CN=Enterprise Admins,CN=Users,$RootDomainDN" }
        @{ Name = "Schema Admins"; Path = "CN=Schema Admins,CN=Users,$RootDomainDN" }
        @{ Name = "Enterprise Key Admins"; Path = "CN=Enterprise Key Admins,CN=Users,$RootDomainDN" }
    )
    
    $params = @{
        ErrorAction = 'SilentlyContinue'
    }
    if (-not [string]::IsNullOrEmpty($Server)) {
        $params['Server'] = $Server
    }
    
    # Verify domain groups exist and add to hashtable
    foreach ($group in $domainGroups) {
        try {
            $adGroup = Get-ADGroup -Identity $group.Path @params
            if ($adGroup) {
                $groups[$group.Name] = $adGroup.DistinguishedName
            }
        }
        catch {
            Write-Verbose "Group not found: $($group.Name)"
        }
    }
    
    # Verify forest groups exist and add to hashtable
    foreach ($group in $forestGroups) {
        try {
            $adGroup = Get-ADGroup -Identity $group.Path @params
            if ($adGroup) {
                $groups[$group.Name] = $adGroup.DistinguishedName
            }
        }
        catch {
            Write-Verbose "Group not found (may not be in forest root): $($group.Name)"
        }
    }
    
    return $groups
}

# Main execution
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SPN Users with Privileged Access" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check for AD module
if (-not (Test-ADModuleAvailable)) {
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

# Get domain information
try {
    $domainParams = @{}
    if (-not [string]::IsNullOrEmpty($Server)) {
        $domainParams['Server'] = $Server
    }
    
    $domain = Get-ADDomain @domainParams
    $forest = Get-ADForest @domainParams
    
    # Get the root domain DN
    $rootDomainDN = (Get-ADDomain -Identity $forest.RootDomain @domainParams).DistinguishedName
    
    Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Green
    Write-Host "[*] Forest: $($forest.Name)" -ForegroundColor Green
    
    # Get all privileged group DNs
    Write-Host "[*] Enumerating privileged groups..." -ForegroundColor Yellow
    $privilegedGroups = Get-PrivilegedGroupDNs -DomainDN $domain.DistinguishedName -RootDomainDN $rootDomainDN -Server $Server
    
    Write-Host "[*] Found $($privilegedGroups.Count) privileged groups to check:" -ForegroundColor Green
    foreach ($groupName in ($privilegedGroups.Keys | Sort-Object)) {
        Write-Host "    - $groupName" -ForegroundColor DarkGray
    }
}
catch {
    Write-Error "Failed to get domain information: $_"
    return
}

# Get all users with SPNs
Write-Host "[*] Searching for users with SPNs..." -ForegroundColor Yellow
$spnUsers = Get-UsersWithSPN -Server $Server -SearchBase $SearchBase

if (-not $spnUsers) {
    Write-Host "[!] No users with SPNs found or query failed." -ForegroundColor Red
    return
}

$spnUserCount = @($spnUsers).Count
Write-Host "[*] Found $spnUserCount user(s) with SPNs" -ForegroundColor Green

# Check each SPN user for privileged group membership
Write-Host "[*] Checking privileged group memberships..." -ForegroundColor Yellow
$results = [System.Collections.ArrayList]::new()

foreach ($user in $spnUsers) {
    $memberships = Test-PrivilegedGroupMembership -User $user -PrivilegedGroups $privilegedGroups -Server $Server
    
    if ($memberships.Count -gt 0) {
        # Format group memberships for display
        $groupList = ($memberships | ForEach-Object { "$($_.GroupName) ($($_.MembershipType))" }) -join '; '
        $directGroups = ($memberships | Where-Object { $_.MembershipType -eq 'Direct' }).GroupName -join '; '
        $nestedGroups = ($memberships | Where-Object { $_.MembershipType -eq 'Nested' }).GroupName -join '; '
        
        $result = [PSCustomObject]@{
            SamAccountName        = $user.SamAccountName
            DisplayName           = $user.DisplayName
            Enabled               = $user.Enabled
            PrivilegedGroups      = $groupList
            DirectMemberships     = $directGroups
            NestedMemberships     = $nestedGroups
            PrivilegedGroupCount  = $memberships.Count
            AdminCount            = $user.AdminCount
            ServicePrincipalNames = ($user.ServicePrincipalName -join '; ')
            PasswordLastSet       = $user.PasswordLastSet
            LastLogonDate         = $user.LastLogonDate
            Description           = $user.Description
            DistinguishedName     = $user.DistinguishedName
        }
        [void]$results.Add($result)
    }
}

# Display results
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($results.Count -eq 0) {
    Write-Host "[+] No users with SPNs found in privileged groups." -ForegroundColor Green
    Write-Host "    This is good from a security perspective.`n" -ForegroundColor Green
}
else {
    Write-Host "[!] WARNING: Found $($results.Count) user(s) with SPNs in privileged groups!`n" -ForegroundColor Red
    Write-Host "    These accounts are vulnerable to Kerberoasting attacks." -ForegroundColor Red
    Write-Host "    If compromised, attackers would gain privileged access.`n" -ForegroundColor Red
    
    # Sort by privilege count (most privileged first)
    $sortedResults = $results | Sort-Object -Property PrivilegedGroupCount -Descending
    
    foreach ($result in $sortedResults) {
        Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "User: " -NoNewline -ForegroundColor White
        Write-Host "$($result.SamAccountName)" -ForegroundColor Yellow
        Write-Host "  Display Name:      $($result.DisplayName)"
        Write-Host "  Enabled:           $($result.Enabled)"
        Write-Host "  Privileged Groups: " -NoNewline
        Write-Host "$($result.PrivilegedGroupCount) group(s)" -ForegroundColor Red
        
        if ($result.DirectMemberships) {
            Write-Host "    Direct:          " -NoNewline -ForegroundColor White
            Write-Host "$($result.DirectMemberships)" -ForegroundColor Magenta
        }
        if ($result.NestedMemberships) {
            Write-Host "    Nested:          " -NoNewline -ForegroundColor White
            Write-Host "$($result.NestedMemberships)" -ForegroundColor DarkMagenta
        }
        
        Write-Host "  Admin Count:       $($result.AdminCount)"
        Write-Host "  Password Set:      $($result.PasswordLastSet)"
        Write-Host "  Last Logon:        $($result.LastLogonDate)"
        Write-Host "  SPNs:              $($result.ServicePrincipalNames)"
        Write-Host "  Description:       $($result.Description)"
    }
    Write-Host "─────────────────────────────────────────`n" -ForegroundColor DarkGray
}

# Export to CSV if requested
if ($ExportCsv -and $results.Count -gt 0) {
    try {
        $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "[*] Results exported to: $ExportCsv`n" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Summary and recommendations
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SUMMARY & RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Total users with SPNs:              $spnUserCount"
Write-Host "SPN users with privileged access:   $($results.Count)"
Write-Host "Privileged groups checked:          $($privilegedGroups.Count)"
Write-Host "Check type:                         Recursive (Direct + Nested)`n"

# Group breakdown
if ($results.Count -gt 0) {
    Write-Host "Breakdown by Group:" -ForegroundColor Yellow
    $allMemberships = $results | ForEach-Object { $_.PrivilegedGroups -split '; ' } | ForEach-Object { ($_ -split ' \(')[0] }
    $groupCounts = $allMemberships | Group-Object | Sort-Object Count -Descending
    foreach ($group in $groupCounts) {
        $riskLevel = switch ($group.Name) {
            "Domain Admins" { "CRITICAL" }
            "Enterprise Admins" { "CRITICAL" }
            "Schema Admins" { "CRITICAL" }
            "Administrators" { "CRITICAL" }
            "Account Operators" { "HIGH" }
            "Server Operators" { "HIGH" }
            "Backup Operators" { "HIGH" }
            "DnsAdmins" { "HIGH" }
            "Key Admins" { "HIGH" }
            "Enterprise Key Admins" { "HIGH" }
            default { "MEDIUM" }
        }
        $color = if ($riskLevel -eq "CRITICAL") { "Red" } elseif ($riskLevel -eq "HIGH") { "Yellow" } else { "White" }
        Write-Host "    $($group.Name): " -NoNewline
        Write-Host "$($group.Count) user(s) " -NoNewline -ForegroundColor $color
        Write-Host "[$riskLevel]" -ForegroundColor $color
    }
    Write-Host ""
    
    Write-Host "Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Remove unnecessary SPNs from privileged accounts"
    Write-Host "  2. Use Group Managed Service Accounts (gMSA) where possible"
    Write-Host "  3. Implement strong, long passwords (25+ characters) for SPN accounts"
    Write-Host "  4. Enable AES encryption and disable RC4 for Kerberos"
    Write-Host "  5. Monitor for Kerberoasting attempts in security logs (Event ID 4769)"
    Write-Host "  6. Consider using Protected Users security group"
    Write-Host "  7. Implement tiered administration model"
    Write-Host "  8. Review nested group memberships for unnecessary privilege paths`n"
}

# Return results for pipeline usage
return $results 
