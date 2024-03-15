Function Invoke-PACLIFileList {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID
    )
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        Safe   = $Safe
        Folder = "ROOT"
    }
    $PACLICommand = "FILESLIST $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir) output`(ENCLOSE,NAME ,ACCESSED ,CREATIONDATE ,CREATEDBY ,DELETIONDATE ,DELETEDBY ,LASTUSEDDATE ,LASTUSEDBY ,LOCKDATE ,LOCKEDBY ,LOCKEDBYGW ,SIZE ,HISTORY ,DRAFT ,RETRIEVELOCK ,INTERNALNAME ,FILEID ,LOCKEDBYUSERID ,VALIDATIONSTATUS`)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    }
    Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        }
        else {
            Throw $PSItem
        }
    
    }
    [System.Collections.ArrayList]$headers = @( "Name", "Accessed", "Creation Date", "Created By", "Deletion Date", "Deleted By",
        "Last Used Date", "Last Used By", "Lock Date", "Locked By", "Locked By Gw", "Size", "History", "Draft",
        "Retrieval Lock", "Internal Name", "FileID", "Locked By UserID", "Validation Status", "Last File Category Update")
    $Cleaned = $Result.StandardOutput | ConvertFrom-Csv -Header $headers
    $Cleaned | Add-Member -MemberType NoteProperty -Name "Safe" -Value $Safe
    $output = @("safe")
    $output += $headers
    return [PSCustomObject]$Cleaned |Select-Object -Property $output
}