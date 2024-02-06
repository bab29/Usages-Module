Function Invoke-PACLISafeClose {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [switch]$Suppress
    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID

    $PACLICommand = "CLOSESAFE SAFE=`"$Safe`""

    Try {
        $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
        IF ($Safe -in $Script:OpenSafeList) {
            $Script:OpenSafeList.remove($safe)
        }
    } Catch {
        If (![string]::IsNullOrEmpty($PSItem.Exception.data.StandardError)) {
            If ($PSItem.Exception.data.StandardError -notmatch "ITATS023E") {
                Write-LogMessage -type Error -MSG "Error while closing safe `"$safe`""
                return
            }
        }
    }
    If (!$Suppress) {
        $output =[PSCustomObject]@{
            Safe = $safe
            Open = "No"
        }
        $output | Format-Table
    }
}