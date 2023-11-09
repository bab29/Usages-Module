Function Get-Usageslist {
        <#
        .SYNOPSIS
        Returns a PSCustomObject of the usages that are in memory
        .DESCRIPTION
        Returns a PSCustomObject of the usages that are in memory
        Loaded via Export-UsagesList or Import-UsagesList
    #>
    return $script:UsagesList
}