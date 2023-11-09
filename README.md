
# Main capabilities
-----------------
Module to migrate usages via PACLI

## Process flow
### Commands used
- Import-Module '.\Usages-Module.psm1' -force
- Set-Location {Location where PACLI is installed}
- Initialize-UsagesModule
- If Source is in PCloud
  - Import-Module 'C:\git\epv-api-scripts\Identity Authentication\IdentityAuth.psm1' (If source is on PCloud Shared Services)
  - $logonToken = Get-IdentityHeader -IdentityTenantURL "{Identity Tenant}" -IdentityUserName "{Identity Username}" (If source is  on PCloud Shared Services)
  - Initialize-Session -PVWAURL "https://{PCloudDomain}.privilegecloud.cyberark.cloud/PasswordVault/" -LogonToken $logonToken
- If Source is On-Prem
  - Initialize-Session -PVWAURL https://pvwa.lab.local/passwordvault/
- Export-UsagesList
- Import-UsagesList
- $PVWAUsages = Get-Usageslist
- Remove-PACLISession -RemoveAllSessions
- Initialize-PACLISession
- Invoke-PACLISessionLogon -vaultIP "192.168.239.30"
- Sync-UsageToPacli -SourceObject $PVWAUsages

## Current limitations

1. Exported accounts are limited to the amounts able to returned by the PVWA
2. Only a single PACLI session can be run at a time which limits operations to one operations at a time
3. Requires PowerShell 7.3 and prevents usage on lower versions of PowerShell
   1. Module will not import in lower versions
   2. For information about how to install PowerShell 7.3 see https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3
## Commands Details
More detailed infomation about paramters are available via Get-Help -Detailed
