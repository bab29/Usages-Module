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
    [string]$AddressRegEx,

    [parameter(Mandatory = $false)] 
    [string]$SourceName,
    [parameter(Mandatory = $false)] 
    [string]$SourceSafe, 

    [parameter(Mandatory = $false)] 
    [string]$CompletedPlatform
)

IF ($(Test-Path -Path "$ConfigFile")) {
    . $ConfigFile
}
Import-Module $ModuleLocation -Force
Initialize-EPVAPIModule
Push-Location (Get-Item $PACLIAPP).Directory.FullName
Try {
    Remove-PACLISession -RemoveAllSessions
    Initialize-PACLISession
    If ([string]::IsNullOrEmpty($cred)) {
        Invoke-PACLISessionCredFile -vaultFile ".\vault.ini" -CredFile ".\user.ini" 
    }
    else {
        Invoke-PACLISessionCredFile -vaultFile ".\vault.ini" -CredFile ".\user.ini" -Credentials $cred
    }

    $SourceObject = Invoke-PACLIFileCategoriesList -target $SourceName -safe $SourceSafe 

    $GetListToAdd = @{
        SafeRegEx     = $SafeRegEx
        PolicyRegEx   = $StagePlatformRegEx
        UsernameRegEx = $UsernameRegEx
        AddressRegEx  = $AddressRegEx
        SourceObject  = $SourceObject
    }
    $list = Get-ListToAdd @GetListToAdd 
    
    $list | ForEach-Object { Try {
        $Target = $PSItem
        Copy-Usage -targetname $Target.File -targetSafe $Target.Safe -targetAddress $Target.Address -SourceName $sourceObject -SourceSafe $sourceSafe
        Invoke-PACLIFileCategoryUpdate -Target $Target.File -Safe $Target.Safe -Catagory "PolicyID" -Value $CompletedPlatform
        Invoke-PACLIFileCategoryDelete -Target $Target.File -Safe $Target.Safe -Catagory "CPMDisabled"
        Invoke-PACLIFileCategoryAdd -Target $Target.File -Safe $Target.Safe -Catagory "ResetImmediately" -Value "ChangeTask"
    } Catch {
        Write-LogMessage -Type Error "Error Processing target file `"$($Target.File)`" in `"$($Target.Safe)`""
    }
}
}	
Finally {
    Invoke-PACLiSessionLogoff
    Remove-PACLISession -RemoveAllSessions
    Pop-Location
}