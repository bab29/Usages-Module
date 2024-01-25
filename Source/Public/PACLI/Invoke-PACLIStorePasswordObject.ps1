Function Invoke-PACLIStorePasswordObject {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [Parameter(Mandatory = $false)]
        [switch]$Suppress

    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        SAFE     = $Safe
        FOLDER   = "ROOT"
        FILE     = $Target
        PASSWORD = ""
    }
    
    $PACLICommand = "STOREPASSWORDOBJECT $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`" and storing password object"
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }

}