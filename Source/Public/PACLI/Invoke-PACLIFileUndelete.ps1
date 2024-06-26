Function Invoke-PACLIFileUndelete {
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
        File   = $file
    }
    $PACLICommand = "UNDELETEFILE $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    } Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS123E .* can not be undeleted because it was not deleted yet.") {
            Write-LogMessage -type Info -MSG "File found but is not deleted. No Action taken."
            return ""
        } elseif ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        } else {
            Throw $PSItem
        }
    }
    $PACLIcmdOrdDir.Add("Status", "Undeleted")
    $Result.StandardOutput | ConvertFrom-Csv -Header Name, Value, Status | ForEach-Object { $PACLIcmdOrdDir.Add($psitem.Name, $psitem.Value,"Undeleted") }
    return [PSCustomObject]$PACLIcmdOrdDir 
}