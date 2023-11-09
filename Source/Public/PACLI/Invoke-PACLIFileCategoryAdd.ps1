Function Invoke-PACLIFileCategoryAdd {
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
        # Category to add
        [Parameter(Mandatory = $true)]
        [string]$Catagory,
        # Value to add
        [Parameter(Mandatory = $true)]
        [string]$Value,
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
        VALUE    = $Value
    }
    
    $PACLICommand = "ADDFILECATEGORY $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`" and adding catagory `"$Catagory`" with the value of `"$value`""
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }

}