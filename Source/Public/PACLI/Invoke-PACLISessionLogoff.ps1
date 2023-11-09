Function Invoke-PACLISessionLogoff{
            <#
        .SYNOPSIS
        Using PACLI logs off the target vault and terminates the PACLI process
        .DESCRIPTION
        PUsing PACLI logs off the target vault and terminates the PACLI process
    #>
    param (
        [int]$PACLISessionID
    )
    $PACLIProcess = Get-PACLISessions
    Try {
        Invoke-Expression "$global:PACLIApp  logoff SESSIONID=$local:PACLIProcess"
        Invoke-Expression "$global:PACLIApp  term SESSIONID=$local:PACLIProcess"
    } Catch {
        $PSItem.ErrorDetails
    }
    [System.Collections.ArrayList]$Script:OpenSafeList = @()
}