Function Get-PACLISessionParameter {
    param (
        [Parameter(Mandatory=$false)]
        [int]$PACLISessionID
    )
    IF (([string]::IsNullOrEmpty($PACLISessionID)) -and ([string]::IsNullOrEmpty($Global:PACLISessionID))) {
        Write-LogMessage -type Error -Message "PACLISessionID was not provided and no global PACLISessionID set"
        Throw "No PACLISessionID found, please run Initialize-PACLISession first"
    } elseif ([string]::IsNullOrEmpty($PACLISessionID)) {
        $local:PACLISessionID = $Global:PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID was not provided, using Global PACLISessionID: $local:PACLISessionID"
    } else {
        $local:PACLISessionID = $global:PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID providede using PACLISessionID: $local:PACLISessionID"
    }
    Return $local:PACLISessionID
}