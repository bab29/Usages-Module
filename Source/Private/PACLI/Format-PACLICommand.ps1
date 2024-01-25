Function Format-PACLICommand {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]
        $cmdOrdDir
    )
    [string]$result = ""
     $cmdOrdDir.Keys | `
            ForEach-Object {
            $result += "$($PSItem)`=`"$($cmdOrdDir[$PSItem])`" "
        }
    Return $result
}