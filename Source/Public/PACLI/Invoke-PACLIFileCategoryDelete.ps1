Function Invoke-PACLIFileCategoryDelete {
    param (

        # File/Object name of the object
        [Parameter(Mandatory = $true)]
        [string]$Target,
        # Safe that contains the File/Object
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        # SessionID to use
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        # Category to delete
        [Parameter(Mandatory = $true)]
        [string]$Catagory,
        # Suppress results output for successes, errors always returned.
        [Parameter(Mandatory = $false)]
        [switch]$Suppress
    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        SAFE     = $Safe
        FOLDER   = "ROOT"
        FILE     = $Target
        CATEGORY = $Catagory
    }
    
    $PACLICommand = "DELETEFILECATEGORY  $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID

    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`" and deleting catagory `"$Catagory`""
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }
}