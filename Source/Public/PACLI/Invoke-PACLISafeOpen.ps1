Function Invoke-PACLISafeOpen {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [switch]$Suppress
    )
    Write-LogMessage -type Debug -msg "Current Open Safe List: $Script:OpenSafeList"
    IF (!(Test-Path variable:Script:OpenSafeList)) {
        [System.Collections.ArrayList]$Script:OpenSafeList = @()
    }
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLICommand = "OPENSAFE SAFE=`"$Safe`" output`(ENCLOSE,NAME,STATUS,SAFEID`)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    IF ($Safe -notin $Script:OpenSafeList) {
        $Script:OpenSafeList += $safe
    }
    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while opening safe `"$safe`""
        return
    }
    If (!$Suppress) {
        $result
    }
}