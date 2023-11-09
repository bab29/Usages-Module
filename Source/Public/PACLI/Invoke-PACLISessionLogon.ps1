Function Invoke-PACLISessionLogon {
            <#
        .SYNOPSIS
        Using PACLI logs onto the target vault and set defaults
        .DESCRIPTION
        Using PACLI logs onto the target vault and set defaults
        Equivlent to running the following commands
        PACLI Define
        PACLI Default
        PACLI Logon
    #>
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
    
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID

    while (($Credentials.password.Length -eq 0) -or [string]::IsNullOrEmpty($Credentials.username)) {
        $Credentials = Get-Credential
        If ($null -eq $Credentials) { return
        }
    }

    Try {
        Invoke-PACLICommand -Command "define vault=`"PCALI$local:PACLISessionID`" address=`"$vaultIP`"" | Out-Null
        Invoke-PACLICommand -Command "default vault=`"PCALI$local:PACLISessionID`" user=`"$($Credentials.username)`" folder=`"Root`"" | Out-Null
        [string]$resultLogon = Invoke-PACLICommand -Command "logon password=$($Credentials.GetNetworkCredential().password)" | Out-Null
        if (![string]::IsNullOrEmpty($resultLogon)) {
            $resultLogon
            Invoke-PACLICommand -Command "logoff SESSIONID=$local:PACLISessionID"
            Invoke-PACLICommand -Command "term SESSIONID=$local:PACLISessionID"
            Write-LogMessage -type Error "Error During logon, PACLI Session Terminated"
            continue
        }
    } Catch {
        $PSItem.ErrorDetails
    }
    [System.Collections.ArrayList]$Script:OpenSafeList = @()
}