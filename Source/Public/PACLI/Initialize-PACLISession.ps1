Function Initialize-PACLISession {

    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]
        $NewSession,
        [ValidateRange(1, 99)]
        [int]
        $PACLISessionID
    )
    If ([string]::IsNullOrEmpty($Global:PACLISessionID)) {
        $local:PACLISessionID = $(Get-Random -Minimum 1 -Maximum 100)
        Write-LogMessage -type Debug -Message "No PACLISessionID provided, generated a random ID of $Local:PACLISessionID"
    }    
    IF ([string]::IsNullOrEmpty($global:PACLIApp)) {
        Set-Variable -Scope Global -Name "PACLIApp"-Value ".\Pacli.exe"
        Write-LogMessage -type Debug -Message "No PACLIApp provided, Set PACLIApp to $global:PACLIApp"
    }
    $PACLIProcess = Get-PACLISessions
    If (([string]::IsNullOrEmpty($PACLIProcess)) -or $NewSession ) {
        Try {
            Invoke-Expression "$global:PACLIApp init SESSIONID=$local:PACLISessionID"
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





