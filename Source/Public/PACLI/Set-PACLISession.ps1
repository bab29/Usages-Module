Function Set-PACLISession{
    param (
        [Parameter()]
        [int]
        $PACLISessionID
    )
    $Global:PACLISessionID = $PACLISessionID
}