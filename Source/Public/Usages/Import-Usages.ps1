Function Import-Usagelist {
    param (
        <#
    Path and filename for use by Export
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
        [ValidatePattern('\.csv$')]
        $importCSV = ".\ExportOfUsages.csv"
    )
    [array]$script:UsagesList = Import-Csv $importCSV -ErrorAction SilentlyContinue
    Write-LogMessage -Type Info -Msg "Imported $($script:UsagesList.count) accounts from `"$importCSV`""
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: Imported Usages: $($script:UsagesList |ConvertTo-Json -Depth 9 -Compress)"
    }
}