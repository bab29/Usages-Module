Function Test-PVWA {
    param(
        [Parameter(Mandatory = $true)]
        [String]$PVWAURL
    )

    If (![string]::IsNullOrEmpty($PVWAURL)) {
        If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
            $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
        }
        try {
            # Validate PVWA URL is OK
            Write-LogMessage -Type Debug -MSG "Trying to validate URL: $PVWAURL"
            Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
        } catch [System.Net.WebException] {
            If (![string]::IsNullOrEmpty($PSItem.Exception.Response.StatusCode.Value__)) {
                Write-LogMessage -Type Error -MSG "Received error $($PSItem.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
                Write-LogMessage -Type Error -MSG "Check your connection to PVWA and the PVWA URL"
                Write-LogMessage -Type Verbose $PSItem
                return
            }
        } catch {
            Write-LogMessage -Type Error -MSG "PVWA URL could not be validated"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $PSItem.Exception) -ErrorAction "SilentlyContinue"

        }

    } else {
        Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
        return
    }

}