
Function Export-Usageslist {
    <#
        .SYNOPSIS
        Exports usages from target
        .DESCRIPTION
        Exports the usages from the target environment using REST API (undocumented)
        Creates CSV file to allow for easy review and import
    #>
    param (
        # File name of the CSV file created
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $exportCSV = ".\ExportOfUsages.csv",

        # URL of PVWA. Must include "/PasswordVault"
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        # Keywords to search by
        # How keywords are searched is controlled by "WideAccountsSearch" and values present in "Search Properties"
        [Parameter(Mandatory = $false)]
        [string]$Keywords,
        # Property to sort results by (Ineffective on exports)
        [Parameter(Mandatory = $false)]
        [string]$SortBy,
        # Name of Safe to Export From
        [Parameter(Mandatory = $false)]
        [string]$SafeName,
        # Limit of accounts to return. 
        # Maximum is controlled via MaxDisplayedRecords
        [Parameter(Mandatory = $false)]
        [string]$Limit=1000,
        # Limit Keyword searches to "StartsWith" instead of default "Contains"
        [Parameter(Mandatory = $false)]
        [boolean]$startswith,
        # PACLI SessionID to use
        [Parameter(Mandatory = $false)]
        [hashtable]$sessionToken
    )
    $excludeProp = @("exportCSV")
    $parms = $PSBoundParameters | Where-Object Values -NE $null | Where-Object Keys -NotIn $excludeProp
    Write-LogMessage -Type Info -Msg "Starting export of usages"

    If ([string]::IsNullOrEmpty($parms)) {
        $usages = Get-Usages
    } else {
        $usages = Get-Usages @parms
    }
    Write-LogMessage -Type Info -Msg "Found $($usages.count) usages"
    Write-LogMessage -Type Info -Msg "Starting export to CSV of $($usages.count) usages"
    $usages = $usages | Where-Object { $PSItem.Safe -notIn $objectSafesToRemove }
    [string[]]$usageProperties = $usages | ForEach-Object { $PSItem.PSObject.Properties.Name } | Select-Object -Unique | Sort-Object
    [string[]]$outputProperties = @("Safe", "MasterPassName", "MasterPassFolder", "PolicyID", "Name", "Username", "Address", "UsageID", "Folder") + $usageProperties | Select-Object -Unique
    $usages | Select-Object $outputProperties | Sort-Object -Property "Safe", "PolicyID", "MasterPassName", "Name" | Export-Csv $exportCSV
    Write-LogMessage -Type Info -Msg "Export of $($usages.count) usages completed."
    New-Variable -Force -Scope Script -Name UsagesList -Value $usages
}
