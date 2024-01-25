function Initialize-Function {
    [CmdletBinding()]
    param ()
    $global:InDebug = $PSBoundParameters.Debug.IsPresent
    $global:InVerbose = $PSBoundParameters.Verbose.IsPresent
    IF (2 -lt (Get-PSCallStack).count) {
        IF (!$global:InDebug) {
            Set-Variable -Scope Global -Name InDebug -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Debug.IsPresent
        }
        If (!$global:InVerbose) {
            Set-Variable -Scope Global -Name InVerbose -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Verbose.IsPresent -ErrorAction SilentlyContinue
        }
    }
}
