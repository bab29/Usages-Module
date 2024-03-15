
param (
    [parameter(Mandatory = $false)] 
    [string]$ConfigFile = "$($(Get-Location).Path)\Invoke-CopyUsages-Config.ps1",

    [parameter(Mandatory = $false)] 
    [string]$PACLIApp = "$($(Get-Location).Path)\Pacli.exe",
    [parameter(Mandatory = $false)] 
    [string]$ModuleLocation = "$($(Get-Location).Path)\EPV-API-Module.psd1",

    [parameter(Mandatory = $false)] 
    [pscredential]$cred,

    [parameter(Mandatory = $false)] 
    [string]$SafeRegEx,
    [parameter(Mandatory = $false)] 
    [string]$StagePlatformRegEx,
    [parameter(Mandatory = $false)] 
    [string]$UsernameRegEx,

    [parameter(Mandatory = $false)] 
    [string]$sourceObject,
    [parameter(Mandatory = $false)] 
    [string]$sourceSafe, 

    [parameter(Mandatory = $false)] 
    [string]$CompletedPlatform
    
)


function Get-ListToAdd {
    param (
        [string]$SafeRegEx,
        [string]$PolicyRegEx,
        [string]$UsernameRegEx
    )
    $MatchSafe = $safeList | Where-Object { $PSItem.Name -Match $SafeRegEx }
    $SafeAccountList = $matchSafe | ForEach-Object { Invoke-PACLIFileFind -safe $PSItem.Name -DelOption WITHOUT_DELETED }
    $SafeAccountListFileCats = $SafeAccountList | ForEach-Object { Invoke-PACLIFileCategoriesList -target $($PSItem.Name) -safe $($PSItem.safe) }
    $AccountPolicy = $SafeAccountListFileCats | Where-Object { $PSItem.PolicyID -Match $PolicyRegEx }
    $AccountUsername = $AccountPolicy | Where-Object { $PSItem.Username -Match $UsernameRegEx }

    $UsagesList = $SafeAccountListFileCats | Where-Object { ![string]::IsNullOrEmpty($PSItem.MasterPassName) `
            -and ($SourceObject.PolicyID -eq $PSItem.PolicyID) `
            -and ($SourceObject.RegistryPathName -eq $PSitem.RegistryPathName) `
            -and ($SourceObject.RegistryValueName -eq $PSitem.RegistryValueName) }

    [pscustomobject[]]$toAddList = $AccountUsername | Where-Object { $PSItem.File -Notin $UsagesList.MasterPassName }

    Return $toAddList
} 

IF (!$(Test-Path -Path "$ConfigFile")) {
    . $ConfigFile
}
Set-Location $PACLIApp
Import-Module $ModuleLocation -Force
Initialize-EPVAPIModule

Try {
    Remove-PACLISession -RemoveAllSessions
    Initialize-PACLISession
    If ([string]::IsNullOrEmpty($cred)) {
        Invoke-PACLISessionCredFile -vaultFile ".\vault.ini" -CredFile ".\user.ini" 
    }
    else {
        Invoke-PACLISessionCredFile -vaultFile ".\vault.ini" -CredFile ".\user.ini" -Credentials $cred
    }

    $GetListToAdd = [pscustomobject]@{
        SafeRegEx     = $SafeRegEx
        PolicyRegEx   = $StagePlatformRegEx
        UsernameRegEx = $UsernameRegEx
    }

    Get-ListToAdd @GetListToAdd | ForEach-Object { 
        Copy-Usage -targetname $PSITem.File -targetSafe $PSItem.Safe -targetAddress $PSITem.Address -SourceName $sourceObject -SourceSafe $safe
        Invoke-PACLIFileCategoryUpdate -Target $PSItem.File -Safe $PSItem.Safe -Catagory "PolicyID" -Value $CompletedPlatform
    }
}
Finally {
    Remove-PACLISession -RemoveAllSessions
}