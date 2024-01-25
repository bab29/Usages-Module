Function Invoke-PACLICommand {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [int]$PACLISessionID = 999,
        [switch]$testSession
    )

    $commandGUID = [guid]::NewGuid().ToString()
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
    Start-Process -FilePath $($global:PACLIApp) -NoNewWindow -Wait -ArgumentList @($Command) -RedirectStandardOutput "$($commandGUID)-Out" -RedirectStandardError "$commandGUID-Error"
    $errorFile = Get-Content ".\$commandGUID-Error"
    Write-LogMessage -type Verbose -Message "Contents of `".\$commandGUID-Error`": $errorFile"
    $outputFile = Get-Content ".\$commandGUID-Out"
    Write-LogMessage -type Verbose -Message "Contents of `".\$commandGUID-Out`": $outputFile"
    [PSCustomObject]$Results = @{
        StandardOutput = $outputFile
        StandardError  = $errorFile 
    }
    Remove-Item -Force -Path ".\$commandGUID-Out"
    Remove-Item -Force -Path ".\$commandGUID-Error"
    If (![string]::IsNullOrEmpty($Results.StandardError)) {
        $Excepetion = [System.Management.Automation.HaltCommandException]::New("Error running PACLI command")
        $Excepetion.Source = $Command
        $Excepetion.Data.Add("StandardOut",$Results.StandardOutput)
        $Excepetion.Data.Add("StandardError",$Results.StandardError)
        Throw $Excepetion
    }
    Return  $Results
}