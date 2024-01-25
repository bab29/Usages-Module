Function Invoke-PACLISessionLogon {
    param (
        [Parameter(Mandatory = $true)]
        [string]$vaultIP,
        [Parameter(Mandatory = $false)]
        [pscredential]$Credentials,
        [int]$PACLISessionID
    )
    $PACLIProcess = Get-PACLISessions
    If ([string]::IsNullOrEmpty($PACLIProcess)) {
        Initialize-PACLISession
    }
    
    $Local:PACLISessionID = Get-PACLISessionParameter  -PACLISessionID $PACLISessionID

    while (($Credentials.password.Length -eq 0) -or [string]::IsNullOrEmpty($Credentials.username)) {
        $Credentials = Get-Credential
        If ($null -eq $Credentials) { return
        }
    }

    Invoke-Expression "$PACLIApp define vault=`"PCALI$local:PACLISessionID`" address=`"$vaultIP`" SESSIONID=$local:PACLISessionID"
    Invoke-Expression "$PACLIApp  default vault=`"PCALI$local:PACLISessionID`" user=`"$($Credentials.username)`" folder=`"Root`" SESSIONID=$local:PACLISessionID"
    [string]$resultLogon = Invoke-Expression "$PACLIApp  logon password=$($Credentials.GetNetworkCredential().password) SESSIONID=$local:PACLISessionID 2>&1"
    if (![string]::IsNullOrEmpty($resultLogon)) {
        $resultLogon
        Invoke-Expression "$PACLIApp  logoff SESSIONID=$local:PACLISessionID"
        Invoke-Expression "$PACLIApp  term SESSIONID=$local:PACLISessionID"
        Write-LogMessage -type Error "Error During logon, PACLI Session Terminated"
        continue
    }
    [System.Collections.ArrayList]$Script:OpenSafeList = @()
}