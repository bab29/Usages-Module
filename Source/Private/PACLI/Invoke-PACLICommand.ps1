Function Invoke-PACLICommand {
    param (
        # Command to be run by PACLI
        [Parameter(Mandatory = $true)]
        [string]$Command,
        #Session number for PACLI to use
        $PACLISessionID = 999,
        #Whether to test that PACLI is successfully connecting to the vault prior to running the command
        [switch]$testSession,
        [switch]$NoWait
    )

    $commandGUID = "PACLI-$([guid]::NewGuid().ToString())"
    Write-LogMessage -type Debug -Message "CommandGUID set to the following: $commandGUID"

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID

    IF ($testSession) {
        Write-LogMessage -type Debug -Message "Testing PACLI Session with PACLISessionID: $local:PACLISessionID"
        Test-PACLISession
    }

    IF ($command -notmatch '\b([1-9]|[1-9][0-9])\b') {
        $Command = "$command SESSIONID=$PACLISessionID"
        Write-LogMessage -type Debug -Message "No SESSIONID found in the command. Added SESSIONID to end of command"
    }

    Write-LogMessage -type Debug -Message "Running the following command: $command"
    [System.Diagnostics.ProcessStartInfo]$PACLIProcessStartInfo = @{
        FileName               = "$global:PACLIApp"
        Arguments              = $Command
        RedirectStandardOutput = $true
        RedirectStandardError  = $true
        CreateNoWindow  = $true
    }
    $PACLIProcessObject = New-Object System.Diagnostics.Process
    $PACLIProcessObject.StartInfo = $PACLIProcessStartInfo
    $PACLIProcessObject.Start() | Out-Null
    $WaitForExit = 60000
    IF ($PACLIProcessObject.WaitForExit($WaitForExit)) {
        [PSCustomObject]$Results = @{
            StandardOutput = $PACLIProcessObject.StandardOutput.ReadToEnd()
            StandardError  = $PACLIProcessObject.StandardError.ReadToEnd()
        }
        If (![string]::IsNullOrEmpty($Results.StandardError)) {
            $Excepetion = [System.Management.Automation.HaltCommandException]::New("Error running PACLI command")
            $Excepetion.Source = $Command
            $Excepetion.Data.Add("StandardOut", $Results.StandardOutput)
            $Excepetion.Data.Add("StandardError", $Results.StandardError)
            Throw $Excepetion
        }
        Return  $Results
    } Else {
        Throw "PACLI Command has run for greater then 60 seconds"
    }
}