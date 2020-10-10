<#
    .SYNOPSIS
    Scan for and or Mitigate Pass The Hash attack vectors.

    .DESCRIPTION
    A simplistic yet powerful pass the hash scanning and 
    mitigation tool for high security Windows environments

    .PARAMETER WDigest
    https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/

    .PARAMETER LSAAdditional
    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

    .PARAMETER LSAAudit
    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

    .PARAMETER RestrictedAdmin
    https://www.stigviewer.com/stig/windows_paw/2017-11-21/finding/V-78161
    https://www.eshlomo.us/restricted-rdp-for-admin-restrictedadmin/
    https://isc.sans.edu/forums/diary/Mitigations+against+Mimikatz+Style+Attacks/24612/

    .PARAMETER Cachelogons
    Change Local Security policy to prevent the cahcing of user account credentials

    .PARAMETER TokenFilterPolicy
    https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction
    https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439

    .EXAMPLE
    C:\PS> ./PowerTheHash.ps1 -WDigest -Cachelogons -RestrictedAdmin

    .EXAMPLE
    C:\PS> ./PowerTheHash.ps1 -WDigest -Cachelogons -RestrictedAdmin -Force
#>

Param(
    [switch]$WDigest = $false,

    [switch]$LSAAdditional = $false,

    [switch]$LSAAudit = $false,

    [switch]$RestrictedAdmin = $false,

    [switch]$Cachelogons = $false,

    [switch]$TokenFilterPolicy = $false,

    [switch]$Force = $false
)

# Registry value exists function
function Test-RegistryValue {

    param (

     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,

    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )

    try {

    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
     return $true
     }

    catch {

    return $false

    }

}

# Check for script arguments
if ($args.Count -eq 0) {
    # Write error message to console and exit
    Write-Error -Message "[Error]: No arguments specified" -Category InvalidArgument
    exit
}

# Switch for each param
if ($Force) {
    Write-Host "[Force]: PowerTheHash will automatically mitigate threats `n" -ForegroundColor Green
}

# Print summary of mitigations/checks to run
Write-host "Summary of checks/mitigations to execute:" -ForegroundColor Green

if ($WDigest) {
    Write-Host "[WDigest]: Disable storage of clear-text passwords in memory" -ForegroundColor Green
}
if ($LSAAdditional) {
    Write-Host "[LSAAdditional]: Enable additional LSA protection" -ForegroundColor Green
}
if ($LSAAudit) {
    Write-Host "[LSAAudit]: Enable auditing mode for LSASS" -ForegroundColor Green
}
if ($RestrictedAdmin) {
    Write-Host "[RestrictedAdmin]: Disable storage of reusable administrative credentials on memory" -ForegroundColor Green
}
if ($Cachelogons) {
    Write-Host "[CacheLogons]: Disable caching of windows credentials" -ForegroundColor Green
}
if ($TokenFilterPolicy) {
    Write-Host "[TokenFilteringPolicy]: Enable remote UAC for local administrators" -ForegroundColor Green
}

$in = Read-Host "Would you like to continue? [y/N]"
if ($in -ne "y") {
    Write-Host "Exiting..." -ForegroundColor Red
}

if ($WDigest) {
    $WDigestExist = Test-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Value "UseLogonCredential"
    if ($WDigestExist -eq $false) {
        Write-Host "[WDigest Vulnerable]: UseLogonCredential registry value not found" -ForegroundColor Red
        $WDigestPossibleForce = $true
    }
    elseif ($WDigestExist -eq $true) {
        $WDigestValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
        if ($WDigestValue -eq 1) {
            Write-Host "[WDigest Vulnerable]: UseLogonCredential registry value set to 1" -ForegroundColor Red
            $WDigestPossibleForce = $true
        }
        elseif ($WDigestValue -eq 0) {
            Write-Host "[WDigest Secure]: UseLogonCredential registry value set to 0" -ForegroundColor Green
        }
        else {
            Write-Host "[WDigest Error]: UseLogonCredential registry value set to obscure value of $WDigestValue" -ForegroundColor Yellow
            $WDigestPossibleForce = $true
        }
    }
    if ($Force -eq $true) {
        if ($WDigestPossibleForce -eq $true) {
            Write-Host "[WDigest]: Creating/Setting UseLogonCredential registry value to 0 " -ForegroundColor Green
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType DWORD -Force
        }
    }
}