Function Invoke-PACLIFileUndelete{
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $true)]
        [string]$File,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID
    )
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        Safe   = $Safe
        Folder = "ROOT"
        File = $file
    }
    $PACLICommand = "UNDELETEFILE $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    } Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        } else {
            Throw $PSItem
        }
    
    }
    $Result.StandardOutput | ConvertFrom-Csv -Header Name, Value | ForEach-Object { $PACLIcmdOrdDir.Add($psitem.Name, $psitem.Value) }
    return [PSCustomObject]$PACLIcmdOrdDir 
}