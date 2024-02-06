Function Remove-PACLISession {

        <#
        .SYNOPSIS
        Removes active PACLISessions
        .DESCRIPTION
        Removes active PACLISessions
        Equivlent to running PACLI TERM
    #>
    param (
        # SessionID to terminate
        [int]$PACLISessionID,
        # Remove all active PACLI Sessions
        [switch]$RemoveAllSessions
    )
    Function RemoveSession {
        param (
            [int]$PACLISessionID
        )
            $null = Invoke-Expression "`"$global:PACLIApp`" term SESSIONID=$PACLISessionID"
            Write-LogMessage -type Info "PACLI session $PACLISessionID removed successful"
    }

    Function RemoveAllSessions {
        $sessions = Get-PACLISessions
        If (![string]::IsNullOrEmpty($sessions)){

        $sessions | ForEach-Object { Invoke-PACLICommand -Command "term" -PACLISessionID $PSItem }
        }
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
        Write-LogMessage -type Info "All PACLI session removed successful and global scope cleared"
    }

    If ($RemoveAllSessions) {
        Write-LogMessage -type Info "Removing all PACLI sessions"
        $null = RemoveAllSessions
    } Elseif (![string]::IsNullOrEmpty($PACLISessionID)) {
        Write-LogMessage -type Info "Removing provided PACLI session $PACLISessionID"
        $null = RemoveSession -PACLISessionID $PACLISessionID
    } Else {
        Write-LogMessage -type Info "Removing global PACLI session $PACLISessionID"
        $null = RemoveSession -PACLISessionID $Global:PACLISessionID
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
    }
}