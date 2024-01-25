Function Get-PACLISessions {
    Function Private:Get-PACLISession {
        Return $(Get-Process -Name "PACLI" -ErrorAction SilentlyContinue)
    }
    $sessions = Get-PACLISession
    $matchesArray = $sessions | ForEach-Object { $($PSItem).CommandLine -match '(?:SESSIONID=)(?<sessionid>\b([0-9]|[1-9][0-9]|100)\b)' | Out-Null; $Matches.SessionID }
    IF ([string]::IsNullOrEmpty($matchesArray)) {
        Return $null
    } else {
        Return [string[]]$($matchesArray)
    }
}
