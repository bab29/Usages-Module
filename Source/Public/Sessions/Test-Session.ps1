Function Test-Session {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param(
        $sessionToken,
        $url
    )
    Function Invoke-Report {
        Write-LogMessage -type Debug -MSG "Error Message attempting to do admin connection: $($RestErrorAdmin.ErrorRecord)"
        IF ([string]::IsNullOrEmpty(!$($RestErrorUser))) {
            Write-LogMessage -type Debug -MSG "Error Message attempting to do user connection: $($RestErrorUser.ErrorRecord)"
        }
    }

    $URL_GetHealthSummery = "$url/API/ComponentsMonitoringSummary/"
    Try {
        $ReturnResultAdmin = Invoke-RestMethod -Method Get -Uri $URL_GetHealthSummery -Headers $sessionToken -ErrorVariable RestErrorAdmin
        Write-LogMessage -Type Verbose -MSG "Test-Session:ReturnResult: $($ReturnResultAdmin|ConvertTo-Json -Depth 9 -Compress)"
        if ((![string]::IsNullOrEmpty($ReturnResultAdmin.Components)) -and ($ReturnResultAdmin.Components.Count -ne 0)) {
            Return $true
        } else {
            Invoke-Report
            return $false
        }
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($PSitem.Exception.Response.StatusCode -eq "Forbidden") {
            $URL_Verify = "$url/API/Verify/"
            $ReturnResultUser = Invoke-RestMethod -Method Get -Uri $URL_Verify -Headers $sessionToken -ErrorVariable RestErrorUser
            IF ([string]::IsNullOrEmpty($ReturnResultUser.ServerName) -or [string]::IsNullOrEmpty(!$RestErrorUser)) {
                Invoke-Report
                Return $false
            } else {
                Invoke-Report
                Write-LogMessage -type Warning -MSG "Connected with a account that is not a member of `"vault admins`". Access to create may be restricted."
                Return $true
            }
        }
    }
}