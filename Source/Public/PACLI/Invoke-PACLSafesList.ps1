Function Invoke-PACLISafesList {
    param (
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID
    )
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
    }

    $headers = @( "Name", "Status", "Lastused", "SafeID")
    $output= ""
    $headers| ForEach-Object {$output = "$output,$PSItem"}

    $PACLICommand = "SAFESLIST $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir) output`(ENCLOSE$($output)`)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    } Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        } else {
            Throw $PSItem
        }
    }
    $Cleaned = $Result.StandardOutput | ConvertFrom-Csv -Header $headers       
    return [PSCustomObject]$Cleaned
}