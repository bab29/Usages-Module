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

    IF ($command -notmatch 'SESSIONID=') {
        $Command = "$command SESSIONID=$PACLISessionID"
        Write-LogMessage -type Debug -Message "No SESSIONID found in the command. Added SESSIONID to end of command"
    }

    Write-LogMessage -type Debug -Message "Running the following command: $command"
    [System.Diagnostics.ProcessStartInfo]$PACLIProcessStartInfo = @{
        FileName               = "$global:PACLIApp"
        Arguments              = $Command
        UseShellExecute        = $False 
        RedirectStandardOutput = $true
        RedirectStandardError  = $true
        CreateNoWindow         = $true
    }
    $PACLIProcessObject = New-Object System.Diagnostics.Process
    $PACLIProcessObject.StartInfo = $PACLIProcessStartInfo
    $PACLIProcessObject.Start() | Out-Null

    $WaitForExit = $Global:WaitForExit


    $Count = 0
    While (!$PACLIProcessObject.HasExited) {
        Write-LogMessage -type Info -Msg "PACLI Still running..."
        Write-LogMessage -type Debug -Message $($PACLIProcessObject | ConvertTo-Json)
        Start-Sleep -Seconds 30
        $count += 1
        IF (60 -lt $count) {
            Write-LogMessage -type Debug -Message $($PACLIProcessObject | ConvertTo-Json)
            Throw "PACLI Command has run for greater then 600 seconds"
        }
    }
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
}

<# 

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
    Write-LogMessage -type Debug -Message $($psitem | ConvertTo-Json)
    Throw "PACLI Command has run for greater then 600 seconds"
}
 #>