Function Remove-PACLISession {
    param (
        [int]$PACLISessionID,
        [switch]$RemoveAllSessions
    )
    Function RemoveSession {
        param (
            [int]$PACLISessionID
        )
            Invoke-Expression "$global:PACLIApp term SESSIONID=$PACLISessionID"
            Write-LogMessage -type Info "PACLI session $PACLISessionID removed successful"
    }

    Function RemoveAllSessions {
        $sessions = Get-PACLISessions
        If (![string]::IsNullOrEmpty($sessions)){
        $sessions | ForEach-Object { Invoke-Expression "$global:PACLIApp term SESSIONID=$PSItem" }
        }
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
        Write-LogMessage -type Info "All PACLI session removed successful and global scope cleared"
    }

    If ($RemoveAllSessions) {
        Write-LogMessage -type Info "Removing all PACLI sessions"
        RemoveAllSessions
    } Elseif (![string]::IsNullOrEmpty($PACLISessionID)) {
        Write-LogMessage -type Info "Removing provided PACLI session $PACLISessionID"
        RemoveSession -PACLISessionID $PACLISessionID
    } Else {
        Write-LogMessage -type Info "Removing global PACLI session $PACLISessionID"
        RemoveSession -PACLISessionID $Global:PACLISessionID
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
    }
}