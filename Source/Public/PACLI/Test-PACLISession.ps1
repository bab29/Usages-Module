Function Test-PACLISession {
    param (
        [int]$PACLISessionID
    )
    
    $Local:PACLISessionID = Get-PACLISessionParameter  -PACLISessionID $PACLISessionID

    $testSafe = "vaultinternal"
    Write-LogMessage -type Debug -Message "Testing PACLISessionID $Local:PACLISessionID"
    $test = Invoke-Command -ScriptBlock {.\Pacli.exe opensafe safe=$testSafe output`(name`) SESSIONID=$Local:PACLISessionID} 
    If ($testsafe -eq $test) {
        Invoke-Command -ScriptBlock {.\Pacli.exe closesafe safe=$testSafe SESSIONID=$Local:PACLISessionID}
        Write-LogMessage -type Info "PACLI test successful"
    } else {
        Remove-PACLISession
        Write-LogMessage -type Debug -Message "Error during test of PACLISessionID $PACLISessionID"
        Throw "Error Opening Test Safe, PACLISession terminated"
    }
}