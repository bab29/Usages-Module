Function Copy-Usage {
    [CmdletBinding(DefaultParameterSetName = 'SoureName')]
    <#
    .SYNOPSIS
    Copy a usage to a new object
    .DESCRIPTION
    Copy a usage to a new object
#>
    param (
        # File/Object name of the new object
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        # Safe to put the new object
        [Parameter(Mandatory = $false)]
        [string]$TargetSafe,
        [Parameter(Mandatory = $true)]
        [string]$TargetAddress,
        # Object to get the file catagories from
        [Parameter(Mandatory = $true, ParameterSetName = 'SourceObject')]
        [pscustomobject]$SourceObject,
        # Object name of the object to get the file catagories from
        [Parameter(Mandatory = $true, ParameterSetName = 'SourceName')]
        [string]$SourceName,
        # Safe to get the object from
        [Parameter(Mandatory = $true, ParameterSetName = 'SourceName')]
        [string]$SourceSafe,
        # SessionID to use
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [switch]$suppress
    )
    If ([string]::IsNullOrEmpty($SourceObject)) {
        $SourceObject = Invoke-PACLIFileCategoriesList -safe $SourceSafe -target $SourceName
    }
    $SourceObject.MasterPassName = $TargetName
    $SourceObject.address = $TargetAddress
    $SourceObject.File = "$TargetName-$($sourceObject.PolicyID)-$TargetAddress"
    If (![string]::IsNullOrEmpty($TargetSafe)) {
        $SourceObject.Safe = $TargetSafe
    }
    New-UsagePACLI -SourceObject $SourceObject -Suppress:$suppress
}