Function Import-Usageslist {
    <#
        .SYNOPSIS
        Imports the CSV of usages
        .DESCRIPTION
        Imports the CSV of usages
        Use Export-Usagelist to create a CSV file for review. Once review and any modifications / removals is completed of that file import using this command. Allows for targeted testing.  
        #>
    param (
        # Path and filename for use by Export
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$importCSV = ".\ExportOfUsages.csv"
    )
    [array]$script:UsagesList = Import-Csv $importCSV -ErrorAction SilentlyContinue
    Write-LogMessage -Type Info -Msg "Imported $($script:UsagesList.count) accounts from `"$importCSV`""
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: Imported Usages: $($script:UsagesList |ConvertTo-Json -Depth 9 -Compress)"
    }
}