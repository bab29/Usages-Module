Function Format-PACLICommand {
    param (
        # Ordered Directory of commands to be formated to the proper format for Invoke-PACLICommand to run
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