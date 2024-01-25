Function Invoke-Rest {
    <#
.SYNOPSIS
	Invoke REST Method
.DESCRIPTION
	Invoke REST Method
.PARAMETER Command
	The REST Command method to run (GET, POST, PATCH, DELETE)
.PARAMETER URI
	The URI to use as REST API
.PARAMETER Header
	The Header as Dictionary object
.PARAMETER Body
	(Optional) The REST Body
.PARAMETER ErrAction
	(Optional) The Error Action to perform in case of error. By default "Continue"
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE", "PATCH", "PUT")]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        $Header,
        [Parameter(Mandatory = $false)]
        [String]$Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
        [String]$ErrAction = "Continue"
    )

    $restResponse = ""
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700 -ErrorAction $ErrAction
        } else {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    } catch [System.Net.WebException] {
        if ($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")) {
            IF (![string]::IsNullOrEmpty($(($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode))) {
                If (($($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -eq "ITATS127E")) {

                    Write-LogMessage -Type Error -Msg "Was able to connect to the PVWA successfully, but the account was locked"
                    Write-LogMessage -Type Error -Msg "URI:  $URI"
                    Throw [System.Management.Automation.RuntimeException] "Account Locked"
                } ElseIf (!($($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -in $global:SkipErrorCode)) {
                    Write-LogMessage -Type Error -Msg "Was able to connect to the PVWA successfully, but the command resulted in a error"
                    Write-LogMessage -Type Error -Msg "URI:  $URI"
                    Write-LogMessage -Type Error -Msg "Command:  $Command"
                    Write-LogMessage -Type Error -Msg "Body:  $Body"
                    Write-LogMessage -Type Error -Msg "Returned ErrorCode: $(($_.ErrorDetails.Message|ConvertFrom-Json).ErrorCode)"
                    Write-LogMessage -Type Error -Msg "Returned ErrorMessage: $(($_.ErrorDetails.Message|ConvertFrom-Json).ErrorMessage)"
                }
            } Else {
                Write-LogMessage -Type Error -Msg "Error Message: $_"
                Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
                Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
                Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
            }
        }
        $restResponse = $null
    } catch {
        IF (![string]::IsNullOrEmpty($(($_ | ConvertFrom-Json -AsHashtable).Details.ErrorMessage))) {
            Throw $($(($_ | ConvertFrom-Json -AsHashtable).Details.ErrorMessage))
        } elseif (![string]::IsNullOrEmpty($(($_ | ConvertFrom-Json -AsHashtable).ErrorMessage))) {
            Throw $($(($_ | ConvertFrom-Json -AsHashtable).ErrorMessage))
        } else {
            Write-LogMessage -Type Error -Msg "Error Message: $_"
            Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
        }
    }
    If ($URI -match "Password/Retrieve") {
        Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: ***********"
    } else {
        Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
    }
    return $restResponse
}