Function Invoke-PACLIFileCategoriesList {
    param (
        # File/Object name of the object to get the file catagories from
        [Parameter(Mandatory = $true)]
        [string]$Target,
        # Safe that contains the File/Object to get values from
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        # SessionID to use
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID
    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        Safe   = $Safe
        Folder = "ROOT"
        File   = $Target
    }

    
    $PACLICommand = "LISTFILECATEGORIES $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir) output`(ENCLOSE,CATEGORYNAME,CATEGORYVALUE`)"
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