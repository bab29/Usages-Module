Build-Module C:\GIT\EPV-API-Module\Source\ -OutputDirectory C:\GIT\EPV-API-Module\Output\EPV-API-Module\ -Verbose

Import-Module 'C:\git\EPV-API-Module\Output\EPV-API-Module\EPV-API-Module.psm1' -Force -Verbose
Set-Location C:\GIT\EPV-API-Module\Source\Public\PACLI

Initialize-EPVAPIModule
$Global:PACLIApp = "C:\GIT\EPV-API-Module\Source\Public\PACLI\Pacli.exe"
$Global:LOG_FILE_PATH = "C:\GIT\EPV-API-Module\Logs\Debug.log"
$Global:InVerbose = $true
$Global:cred = New-Object System.Management.Automation.PSCredential -ArgumentList("Administrator", $("Cyberark1!" | ConvertTo-SecureString -AsPlainText -Force))
Convert-Breakpoint
Remove-PACLISession -RemoveAllSessions
Initialize-PACLISession
Invoke-PACLISessionLogon -vaultIP "192.168.239.30" -Credentials $cred
#Undelete Tests
Invoke-PACLISafeOpen -safe BABPERMTEST
$deltest = Invoke-PACLIFileFind -safe BABPERMTEST -DelOption ONLY_DELETED
if (![string]::IsNullOrEmpty($deltest)) {
    $deltest | ForEach-Object { Invoke-PACLIFileUndelete -safe $($PSItem.Safe) -file $($PSItem.Name) }
}
Invoke-PACLISafeClose -safe BABPERMTEST
"Done"