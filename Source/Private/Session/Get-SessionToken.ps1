
Function Get-SessionToken {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        [Parameter(Mandatory = $false)]
        [string]$AuthType = $script:AuthType,
        [Parameter(Mandatory = $false)]
        [string]$OTP
    )

    $URL_Logon = "$url/api/auth/$AuthType/Logon"

    $sesionBody = @{ 
        username          = $Credentials.username.Replace('\', ''); 
        password          = $Credentials.GetNetworkCredential().password; 
        concurrentSession = "true" 
    } | ConvertTo-Json -Compress
    
    If (![string]::IsNullOrEmpty($RadiusOTP)) {
        $sesionBody.Password += ",$RadiusOTP"
    }

    try {
        $sessionToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $sesionBody
    } catch {
        Write-LogMessage -Type Verbose $PSItem
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($PSItem.Exception.Response.StatusDescription)", $PSItem.Exception))
    } finally {
        $sesionBody = $null
    }

    If ([string]::IsNullOrEmpty($sessionToken)) {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }
    $sessionToken = @{Authorization = $sessionToken }
    return $sessionToken
}