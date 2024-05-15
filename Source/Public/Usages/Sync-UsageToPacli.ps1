Function Sync-UsageToPacli {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        Using the PSCustomObject array passed, creates the usages in target vault via PACLI
        .DESCRIPTION
        Using the PSCustomObject array passed, creates or modifies existing usages in target vault via PACLI
        Single threaded process
        Object requires the minimun of the following properties:
            Name, UsageID, UsageInfo, Safe, Folder, File
        Any additional properties will be added
        .NOTES
        If a usage was deleted, but a version still exists in the safe, the prior version will be restored and then updated.
        #>
    param(
        # The object to be processed.

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $SourceObject,
        [switch]
        $suppress
    )
    # Kept in place for backwards compatibility
    return $($SourceObject | New-UsagePACLI -Suppress:$suppress)
}