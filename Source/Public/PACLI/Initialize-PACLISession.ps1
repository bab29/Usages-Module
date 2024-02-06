Function Initialize-PACLISession {
        <#
        .SYNOPSIS
        Starts PACLI and sets SessionID
        .DESCRIPTION
        Starts PACLI and sets SessionID
        Equivlent to PACLI INIT
    #>
    [CmdletBinding()]
    param (
        # Create a new session instead of using a existing session
        [Parameter()]
        [switch]
        $NewSession,
        # Use a specific value between 1 and 99 as the session ID number
        [ValidateRange(1, 99)]
        [int]
        $PACLISessionID
    )

    If ([string]::IsNullOrEmpty($Global:PACLISessionID) -or (0 -eq $Global:PACLISessionID)) {
        $local:PACLISessionID = $(Get-Random -Minimum 1 -Maximum 100)
        Write-LogMessage -type Debug -Message "No PACLISessionID provided, generated a random ID of $Local:PACLISessionID"
    }    
    IF ([string]::IsNullOrEmpty($global:PACLIApp)) {
        Set-Variable -Scope Global -Name "PACLIApp" -Value ".\Pacli.exe"
        Write-LogMessage -type Debug -Message "No PACLIApp provided, Set PACLIApp to $global:PACLIApp"
    }
    $PACLIProcess = Get-PACLISessions
    If (([string]::IsNullOrEmpty($PACLIProcess) -or (0 -eq $PACLIProcess)) -or $NewSession ) {
        Try {
            $null = Invoke-PACLICommand -Command "init SESSIONID=$local:PACLISessionID" -NoWait
            Write-LogMessage -type Debug -Message "New PALCI session initizaed with a ID of $local:PACLISessionID"
        } catch {
            Throw $_
        }
    } else {
        Write-LogMessage -type Warning -Message "PACLISession already exists. To create a new session use the switch NewSession. Existing PACLI Session IDs: $([string]$PACLIProcess)"
        Continue
    } 

    IF ([string]::IsNullOrEmpty($global:PACLISessionID)) {
        $global:PACLISessionID = $local:PACLISessionID
        Write-LogMessage -type Debug -Message "No global PALCI session ID set, set Global PACLI session ID to $global:PACLISessionID"
    }
    Return $local:PACLISessionID
}





