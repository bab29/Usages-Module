function Initialize-Session {

    <#
        .SYNOPSIS
        Connects to the source PVWA
        .DESCRIPTION
        Connects to the source PVWA and tests the connection to ensure the supplied credentials/LogonToken are working
    #>
    [CmdletBinding()]
    param (
        # URL for the environment
        #- HTTPS://Destination.lab.local/PasswordVault
    
        [Parameter(Mandatory = $false)]
        [Alias("URL")]
        [String]$PVWAURL,
        # Authentication types for logon.
        # - Available values: _CyberArk, LDAP, RADIUS_
        # - Default value: _CyberArk_
        [Parameter(Mandatory = $false)]
        [ValidateSet("cyberark", "ldap", "radius")]
        [String]$AuthType = "cyberark",
        #One Time Password for use with RADIUS
        [Parameter(Mandatory = $false)]
        $otp,
        # Credentials for source environment
        [Parameter(Mandatory = $false)]
        [PSCredential]$PVWACredentials,
        # Headers for use with environment
        # - Used with Privileged Cloud environment
        # - When used, log off is suppressed in the environment
        [Parameter(Mandatory = $false)]
        $logonToken,
        # Use this switch to Disable SSL verification (NOT RECOMMENDED)
        [Parameter(Mandatory = $false)]
        [Switch]$DisableSSLVerify
    )
    Initialize-Function
    Test-PVWA -PVWAURL $PVWAURL
    If (![string]::IsNullOrEmpty($logonToken)) {
        Write-LogMessage -Type Info -MSG "Setting Logon Token"
        if ($logonToken.GetType().name -eq "String") {
            $logonHeader = @{Authorization = $logonToken }
            Set-Variable -Scope Script -Name sessionToken -Value $logonHeader -Force   
        } else {
            Set-Variable -Scope Script -Name sessionToken -Value $logonToken -Force
        }
    } else {
        If ([string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
        } 
        New-Variable -Name AuthType -Value $AuthType -Scope Script -Force

        New-Variable -Scope script -Name sessionToken -Value $(Get-SessionToken -Credentials $PVWACredentials -AuthType $AuthType -URL $PVWAURL -OTP $OTP) -Force

        If ($null -eq $script:sessionToken) {
            Write-LogMessage -Type Error -MSG "No sessionToken generated" -Footer
            return 
        }
    }

    New-Variable -Scope script -Name PVWAURL -Value $PVWAURL -Force
    if (Test-Session -sessionToken $script:sessionToken -url $script:PVWAURL) {
        Write-LogMessage -type Info -MSG "Session successfully configured and tested"
        Write-LogMessage -type Debug -MSG "Token set to $($script:sessionToken |ConvertTo-Json -Depth 10)"
    } else {
        Write-LogMessage -type Error -MSG "Session failed to connect successfully"
    }
}
