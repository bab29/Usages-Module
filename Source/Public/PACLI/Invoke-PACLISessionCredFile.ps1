Function Invoke-PACLISessionCredFile {
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
        [Parameter(Mandatory = $false)]
        [string]$vaultIP,
        [Parameter(Mandatory = $false)]
        [string]$vaultFile,
        [Parameter(Mandatory = $true)]
        [string]$CredFile,
        [Parameter(Mandatory = $false)]
        [pscredential]$Credentials,
        [int]$PACLISessionID
    )
    $PACLIProcess = Get-PACLISessions
    If ([string]::IsNullOrEmpty($PACLIProcess)) {
        Initialize-PACLISession
    }
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $vaultID = "PCALI$local:PACLISessionID"
    $credlocation = (Get-Item $CredFile).FullName
    If ($null -ne $Credentials) { 
        [string]$resultLogon = Invoke-PACLICommand -Command "CREATELOGONFILE LOGONFILE=`"$credlocation`" USERNAME=`"$($Credentials.username)`" PASSWORD=`"$($Credentials.GetNetworkCredential().password)`""  | Out-Null
    } 
    $username = ((Get-Content $credFile) -match '(^Username=.*)').Replace("Username=", "")
    Try {
        If (![string]::IsNullOrEmpty($vaultFile)){
            $vaultID  = ((Get-Content $vaultFile) -match '(^VAULT.*=)').Replace(" ","").Replace("VAULT=", "").Trim().replace("`"","")
            Invoke-PACLICommand -Command "DEFINEFROMFILE vault=`"$vaultID`" PARMFILE=`"$($(Get-Item $vaultFile).FullName)`"" | Out-Null
        } else {
            Invoke-PACLICommand -Command "define vault=`"$vaultID`" address=`"$vaultIP`"" | Out-Null
        }
        Invoke-PACLICommand -Command "default vault=`"$vaultID`" user=`"$username`" folder=`"Root`"" | Out-Null        
        [string]$resultLogon = Invoke-PACLICommand -Command "LOGON VAULT=`"$vaultID`" USER=`"$username`" LOGONFILE=`"$credlocation`"" | Out-Null
        if (![string]::IsNullOrEmpty($resultLogon)) {
            $resultLogon
            Invoke-PACLICommand -Command "logoff SESSIONID=$local:PACLISessionID"
            Invoke-PACLICommand -Command "term SESSIONID=$local:PACLISessionID"
            Write-LogMessage -type Error "Error During logon, PACLI Session Terminated"
            continue
        }
    }
    Catch {
        (Get-Error -last 1).Exception.data.StandardError
        Throw
    }
    [System.Collections.ArrayList]$Script:OpenSafeList = @()
}