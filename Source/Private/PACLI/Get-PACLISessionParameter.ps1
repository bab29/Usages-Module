Function Get-PACLISessionParameter {
    param (

        # PACLI Session number to use based on the Global PACLISessionID variable
        [Parameter(Mandatory=$false)]
        $PACLISessionID
    )
    IF (([string]::IsNullOrEmpty($PACLISessionID)) -and ([string]::IsNullOrEmpty($Global:PACLISessionID))) {
        Write-LogMessage -type Error -Message "PACLISessionID was not provided and no global PACLISessionID set"
        Throw "No PACLISessionID found, please run Initialize-PACLISession first"
    } elseif ([string]::IsNullOrEmpty($PACLISessionID)) {
        $local:PACLISessionID = $Global:PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID was not provided, using Global PACLISessionID: $local:PACLISessionID"

    } elseif ((999 -eq $PACLISessionID)) {
        $local:PACLISessionID = $Global:PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID of 999 provided. Command being requested is Initialize-PACLISession without specific sessionID to be used passed"
    }
    else {
        $local:PACLISessionID = $PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID provided using PACLISessionID: $local:PACLISessionID"
    }
    Return $local:PACLISessionID
}