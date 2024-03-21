function Get-ListToAdd {
    [CmdletBinding()]
    param (
        [string]$SafeRegEx,
        [string]$PolicyRegEx,
        [string]$UsernameRegEx,
        [string]$AddressRegEx,
        [String]$SourceObject
    )

    $safelist = Invoke-PACLISafesList
    $MatchSafe = $safeList | Where-Object { $PSItem.Name -Match $SafeRegEx }
    $SafeAccountList = $matchSafe | ForEach-Object { Invoke-PACLIFileFind -safe $PSItem.Name -DelOption WITHOUT_DELETED }
    $SafeAccountListFileCats = $SafeAccountList | ForEach-Object { Invoke-PACLIFileCategoriesList -target $($PSItem.Name) -safe $($PSItem.safe) }
    $AccountPolicy = $SafeAccountListFileCats | Where-Object { $PSItem.PolicyID -Match $PolicyRegEx }
    $AccountAddress = $AccountPolicy | Where-Object { $PSItem.Address -Match $AddressRegEx }
    $AccountUsername = $AccountAddress | Where-Object { $PSItem.Username -Match $UsernameRegEx }

    $UsagesList = $SafeAccountListFileCats | Where-Object { ![string]::IsNullOrEmpty($PSItem.MasterPassName) `
            -and ($SourceObject.PolicyID -eq $PSItem.PolicyID) `
            -and ($SourceObject.RegistryPathName -eq $PSitem.RegistryPathName) `
            -and ($SourceObject.RegistryValueName -eq $PSitem.RegistryValueName) }

    [pscustomobject[]]$toAddList = $AccountUsername | Where-Object { $PSItem.File -Notin $UsagesList.MasterPassName }

    Return $toAddList
} 
