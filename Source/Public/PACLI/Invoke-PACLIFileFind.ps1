Function Invoke-PACLIFileFind {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INCLUDE_DELETED_WITH_ACCESSMARKS", "INCLUDE_DELETED", "ONLY_DELETED", "WITHOUT_DELETED")]
        [String]$DelOption = "INCLUDE_DELETED_WITH_ACCESSMARKS"
    )
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        Safe   = $Safe
        Folder = "ROOT"
    }
    $PACLICommand = "FINDFILES $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir) DELETEDOPTION=$DelOption output`(ALL,ENCLOSE`)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    } Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        } else {
            Throw $PSItem
        }
    }
    if ([string]::IsNullOrEmpty($result.StandardOutput)) {
        Write-LogMessage -type Info -MSG "No Results found"
        return ""
    }
    $headers = @( "Name", "Accessed", "Creation Date", "Created By", "Deletion Date", "Deleted By",
        "Last Used Date", "Last Used By", "Lock Date", "Locked By", "Locked By Gw", "Size", "History", "
    Internalname", "Safe", "Folder", "File ID", "Locked By User Id", "Validation Status", "Human Creation Date",
        "Human Created By", "Human Last Used Date", "Human Last Used By", "Human Last Retrieved By Date", "
    Human Last Retrieved By", "Component Creation Date", "Component Created By", "Component Last Used Date",
        "Component Last Used By", "Component Last Retrieved Date", "Component Last Retrieved By", "File Categories")
    $Cleaned = $Result.StandardOutput | ConvertFrom-Csv -Header $headers       
    return [PSCustomObject]$Cleaned
}