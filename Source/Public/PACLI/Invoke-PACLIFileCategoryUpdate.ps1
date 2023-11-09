Function Invoke-PACLIFileCategoryUpdate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [Parameter(Mandatory = $true)]
        [string]$Catagory,
        [Parameter(Mandatory = $true)]
        [string]$Value,
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
    
    $PACLICommand = "UPDATEFILECATEGORY $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID

    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`"  and updating catagory `"$Catagory`" with the value of `"$value`""
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }
}