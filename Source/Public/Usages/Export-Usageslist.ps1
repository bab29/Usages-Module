Function Export-Usageslist {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $exportCSV = ".\ExportOfUsages.csv",
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        [Parameter(Mandatory = $false)]
        [string]$Keywords,
        [Parameter(Mandatory = $false)]
        [string]$SortBy,
        [Parameter(Mandatory = $false)]
        [string]$SafeName,
        [Parameter(Mandatory = $false)]
        [string]$Limit,
        [Parameter(Mandatory = $false)]
        [boolean]$startswith,
        [Parameter(Mandatory = $false)]
        [hashtable]$sessionToken
    )

    $parms = $PSBoundParameters | Where-Object Values -NE $null
    Write-LogMessage -Type Info -Msg "Starting export of usages"
    If ([string]::IsNullOrEmpty($parms)) {
        $usages = Get-Usages
    } else {
        $usages = Get-Usages @parms
    }
    Write-LogMessage -Type Info -Msg "Found $($usages.count) usages"
    Write-LogMessage -Type Info -Msg "Starting export to CSV of $($usages.count) usages"
    $usages | `
            Where-Object { $_.safename -notIn $objectSafesToRemove } | `
            Export-Csv -Path $exportCSV -NoTypeInformation
    Write-LogMessage -Type Info -Msg "Export of $($usages.count) usages completed."
    New-Variable -Force -Scope Script -Name UsagesList -Value $usages
}
