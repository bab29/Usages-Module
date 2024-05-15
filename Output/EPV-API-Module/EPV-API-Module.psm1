#Region '.\Private\_Common\Compare-Stuff.ps1' -1

function Compare-Stuff {
    [CmdletBinding()]
    param (
        $ReferenceObject, 
        $DifferenceObject, 
        $MaxDepth = -1, 
        [switch]$IncludeEqual, 
        [switch]$ExcludeDifferent, 
        [switch]$PassThru, 
        [switch]$Compact,
        [switch]$namesOnly,
        [parameter(DontShow)]
        $__Property, 
        [parameter(DontShow)]
        $__Depth = 0 
    )

    # Parameter help description
 
    if ($MaxDepth -eq -1 -or $__Depth -le $MaxDepth) {
        #check for arrays of PSCustomObjects or arrays of custom class and iterate over those
        if (($ReferenceObject -is [array]) -and ($ReferenceObject[0] -is [PSCustomObject] -or $null -eq $ReferenceObject[0].GetType().Namespace)) {
            $__Depth++
            for ($i = 0; $i -lt $ReferenceObject.Count; $i++) {
                #recurse carrying the current Property name + index and Depth values forward
                Compare-Stuff $ReferenceObject[$i] $DifferenceObject[$i] -__Property ($__Property + "[$i]") -__Depth $__Depth -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru -Compact:$Compact -namesOnly:$namesOnly
            }
        }
        #check for custom classes or PSCustomObjects and iterate over their properties.
        elseif ($ReferenceObject -is [PSCustomObject] -or $null -eq $ReferenceObject.GetType().Namespace) {
            $__Depth++
            foreach ($prop in $ReferenceObject.PSObject.properties.name) {
                #build up the property name hierarchy
                $newProp = $prop
                if ($__Property) {
                    $newProp = $__Property + '.' + $prop
                }
                # handle ref. or diff. objects equal null
                $refValue = $ReferenceObject.$prop
                $diffValue = $DifferenceObject.$prop
                if ($Null -eq $refValue) {
                    $refValue = ''
                }
                if ($null -eq $diffValue) {
                    $diffValue = ''
                }
                #recurse carrying the current Property and Depth values forward
                Compare-Stuff $refValue $diffValue -__Property $newProp -__Depth $__Depth -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru -Compact:$Compact -namesOnly:$namesOnly
            }
        } else {
            #if we reach here we are dealing with a scalar or array of scalars that the built-in cmdlet can already deal with
            $output = Compare-Object $ReferenceObject $DifferenceObject -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru |
                Select-Object @{n = 'Property'; e = { $__Property } }, @{n = 'Value'; e = { $_.InputObject } }, SideIndicator
            if ($Compact) {
                $output | Group-Object Property, { $_.SideIndicator -eq '==' } | ForEach-Object {
                    if ($_.Group[0].SideIndicator -eq '==') {
                        [PSCustomObject][Ordered]@{
                            Property        = $_.Group.Property
                            ReferenceValue  = $_.Group.Value
                            DifferenceValue = $_.Group.Value
                        }
                    } else {
                        [PSCustomObject][Ordered]@{
                            Property        = $_.Group[0].Property
                            ReferenceValue  = ($_.Group.where{ $_.SideIndicator -eq '<=' }).Value
                            DifferenceValue = ($_.Group.where{ $_.SideIndicator -eq '=>' }).Value
                        }
                    }
                }
            } elseif ($namesOnly) {
                $output | Where-Object -Property SideIndicator -eq "<="| Select-Object -Property Property,Value -Unique 
            } Else {
                $output
            }
        }
    }
}
#EndRegion '.\Private\_Common\Compare-Stuff.ps1' 78
#Region '.\Private\_Common\Initialize-Function.ps1' -1

function Initialize-Function {
    [CmdletBinding()]
    param ()
    $global:InDebug = $PSBoundParameters.Debug.IsPresent
    $global:InVerbose = $PSBoundParameters.Verbose.IsPresent
    IF (2 -lt (Get-PSCallStack).count) {
        IF (!$global:InDebug) {
            Set-Variable -Scope Global -Name InDebug -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Debug.IsPresent
        }
        If (!$global:InVerbose) {
            Set-Variable -Scope Global -Name InVerbose -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Verbose.IsPresent -ErrorAction SilentlyContinue
        }
    }
}
#EndRegion '.\Private\_Common\Initialize-Function.ps1' 15
#Region '.\Private\_Common\Invoke-Rest.ps1' -1

Function Invoke-Rest {
    <#
.SYNOPSIS
	Invoke REST Method
.DESCRIPTION
	Invoke REST Method
.PARAMETER Command
	The REST Command method to run (GET, POST, PATCH, DELETE)
.PARAMETER URI
	The URI to use as REST API
.PARAMETER Header
	The Header as Dictionary object
.PARAMETER Body
	(Optional) The REST Body
.PARAMETER ErrAction
	(Optional) The Error Action to perform in case of error. By default "Continue"
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE", "PATCH", "PUT")]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        $Header,
        [Parameter(Mandatory = $false)]
        [String]$Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
        [String]$ErrAction = "Continue"
    )

    $restResponse = ""
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700 -ErrorAction $ErrAction
        } else {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    } catch [System.Net.WebException] {
        if ($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")) {
            IF (![string]::IsNullOrEmpty($(($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode))) {
                If (($($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -eq "ITATS127E")) {

                    Write-LogMessage -Type Error -Msg "Was able to connect to the PVWA successfully, but the account was locked"
                    Write-LogMessage -Type Error -Msg "URI:  $URI"
                    Throw [System.Management.Automation.RuntimeException] "Account Locked"
                } ElseIf (!($($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -in $global:SkipErrorCode)) {
                    Write-LogMessage -Type Error -Msg "Was able to connect to the PVWA successfully, but the command resulted in a error"
                    Write-LogMessage -Type Error -Msg "URI:  $URI"
                    Write-LogMessage -Type Error -Msg "Command:  $Command"
                    Write-LogMessage -Type Error -Msg "Body:  $Body"
                    Write-LogMessage -Type Error -Msg "Returned ErrorCode: $(($_.ErrorDetails.Message|ConvertFrom-Json).ErrorCode)"
                    Write-LogMessage -Type Error -Msg "Returned ErrorMessage: $(($_.ErrorDetails.Message|ConvertFrom-Json).ErrorMessage)"
                }
            } Else {
                Write-LogMessage -Type Error -Msg "Error Message: $_"
                Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
                Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
                Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
            }
        }
        $restResponse = $null
    } catch {
        IF (![string]::IsNullOrEmpty($(($_ | ConvertFrom-Json -AsHashtable).Details.ErrorMessage))) {
            Throw $($(($_ | ConvertFrom-Json -AsHashtable).Details.ErrorMessage))
        } elseif (![string]::IsNullOrEmpty($(($_ | ConvertFrom-Json -AsHashtable).ErrorMessage))) {
            Throw $($(($_ | ConvertFrom-Json -AsHashtable).ErrorMessage))
        } else {
            Write-LogMessage -Type Error -Msg "Error Message: $_"
            Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
        }
    }
    If ($URI -match "Password/Retrieve") {
        Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: ***********"
    } else {
        Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
    }
    return $restResponse
}
#EndRegion '.\Private\_Common\Invoke-Rest.ps1' 84
#Region '.\Private\_Common\New-SearchCriteria.ps1' -1

Function New-SearchCriteria {
    param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [boolean]$startswith, [int]$iLimitPage, [int]$iOffsetPage = 0)
    [string]$retURL = $sURL
    $retURL += "?"
	
    if (![string]::IsNullOrEmpty($sSearch)) {
        Write-LogMessage -Type Debug -Msg "Search: $sSearch"
        $retURL += "search=$(Convert-ToURL $sSearch)&"
    }
    if (![string]::IsNullOrEmpty($sSafeName)) {
        Write-LogMessage -Type Debug -Msg "Safe: $sSafeName"
        $retURL += "filter=safename eq $(Convert-ToURL $sSafeName)&"
    }
    if (![string]::IsNullOrEmpty($sSortParam)) {
        Write-LogMessage -Type Debug -Msg "Sort: $sSortParam"
        $retURL += "sort=$(Convert-ToURL $sSortParam)&"
    }
    if ($startswith) {
        Write-LogMessage -Type Debug -Msg "startswith: $sSortParam"
        $retURL += "searchtype=startswith"
    }
    if ($iLimitPage -gt 0) {
        Write-LogMessage -Type Debug -Msg "Limit: $iLimitPage"
        $retURL += "limit=$iLimitPage&"
    }
		
    if ($retURL[-1] -eq '&') {
        $retURL = $retURL.substring(0, $retURL.length - 1) 
    }
    Write-LogMessage -Type Debug -Msg "URL: $retURL"
	
    return $retURL
}
#EndRegion '.\Private\_Common\New-SearchCriteria.ps1' 34
#Region '.\Private\_Common\Write-LogMessage.ps1' -1

Function Write-LogMessage {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type
.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [alias("Message")]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $script:LOG_FILE_PATH
    )

    Try {
        If ([string]::IsNullOrEmpty($LogFile) -and $(!([string]::IsNullOrEmpty($global:LOG_FILE_PATH)))) {
            $LogFile = $script:LOG_FILE_PATH = $Global:LOG_FILE_PATH
            Write-Host "No log file path passed or found in the module, setting log file path to the global value of: `"$LogFile`""
        } elseIf ([string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            $script:LOG_FILE_PATH = $LogFile
            Write-Host "No log file path inputted and no global value found, setting modoule log file path to: `"$LogFile`""
        }
        If ($Header -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        } ElseIf ($SubHeader -and $WriteLog) {
            "------------------------------------" | Out-File -Append -FilePath $LogFile
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }

        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A"
        }
        $msgToWrite = ""

        # Change SecretType if password to prevent masking issues

        $Msg = $Msg.Replace('"secretType":"password"', '"secretType":"pass"')

        # Mask Passwords
        #TODO Update to use regex group to do replacement
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }

        If ($maskAnswer) {
            $Msg -match '(?:\\"Answer\\":\\")(?<Mask>.*?)(?:\\")' | Out-Null
            $Msg = $Msg.Replace($Matches.Mask, "<Value Masked>")
        }


        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } {
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                            "Magenta"
                        } Else {
                            "Gray"
                        })
                }
                $msgToWrite = "[INFO]`t$Msg"
                break
            }
            "Success" {
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite = "[SUCCESS]`t$Msg"
                break
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite = "[WARNING]`t$Msg"
                break
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite = "[ERROR]`t$Msg"
                break
            }
            "Debug" {
                if ($InDebug -or $InVerbose) {
                    Write-Debug -Msg $MSG
                    $msgToWrite = "[Debug]`t$Msg"
                }
                break
            }
            "Verbose" {
                if ($InVerbose) {
                    Write-Verbose -Msg $MSG
                    $msgToWrite = "[VERBOSE]`t$Msg"
                }
                break
            }
        }

        If ($WriteLog) {
            If (![string]::IsNullOrEmpty($msgToWrite)) {
                "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
            }
        }
        If ($Footer -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    } catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}
#EndRegion '.\Private\_Common\Write-LogMessage.ps1' 138
#Region '.\Private\PACLI\Format-PACLICommand.ps1' -1

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
#EndRegion '.\Private\PACLI\Format-PACLICommand.ps1' 15
#Region '.\Private\PACLI\Get-PACLISessionParameter.ps1' -1

Function Get-PACLISessionParameter {
    param (

        # PACLI Session number to use based on the Global PACLISessionID variable
        [Parameter(Mandatory=$false)]
        $PACLISessionID
    )
    IF (([string]::IsNullOrEmpty($PACLISessionID)) -and ([string]::IsNullOrEmpty($Global:PACLISessionID))) {
        Write-LogMessage -type Error -Message "PACLISessionID was not provided and no global PACLISessionID set"
        Throw "No PACLISessionID found, please run Initialize-PACLISession first"
    } elseif ([string]::IsNullOrEmpty($PACLISessionID)) {
        $local:PACLISessionID = $Global:PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID was not provided, using Global PACLISessionID: $local:PACLISessionID"

    } elseif ((999 -eq $PACLISessionID)) {
        $local:PACLISessionID = $Global:PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID of 999 provided. Command being requested is Initialize-PACLISession without specific sessionID to be used passed"
    }
    else {
        $local:PACLISessionID = $PACLISessionID
        Write-LogMessage -type Debug -Message "PACLISessionID provided using PACLISessionID: $local:PACLISessionID"
    }
    Return $local:PACLISessionID
}
#EndRegion '.\Private\PACLI\Get-PACLISessionParameter.ps1' 25
#Region '.\Private\PACLI\Invoke-PACLICommand.ps1' -1

Function Invoke-PACLICommand {
    param (
        # Command to be run by PACLI
        [Parameter(Mandatory = $true)]
        [string]$Command,
        #Session number for PACLI to use
        $PACLISessionID = 999,
        #Whether to test that PACLI is successfully connecting to the vault prior to running the command
        [switch]$testSession,
        [switch]$NoWait
    )

    $commandGUID = "PACLI-$([guid]::NewGuid().ToString())"
    Write-LogMessage -type Debug -Message "CommandGUID set to the following: $commandGUID"

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID

    IF ($testSession) {
        Write-LogMessage -type Debug -Message "Testing PACLI Session with PACLISessionID: $local:PACLISessionID"
        Test-PACLISession
    }

    IF ($command -notmatch 'SESSIONID=') {
        $Command = "$command SESSIONID=$PACLISessionID"
        Write-LogMessage -type Debug -Message "No SESSIONID found in the command. Added SESSIONID to end of command"
    }

    Write-LogMessage -type Debug -Message "Running the following command: $command"
    [System.Diagnostics.ProcessStartInfo]$PACLIProcessStartInfo = @{
        FileName               = "$global:PACLIApp"
        Arguments              = $Command
        UseShellExecute        = $False 
        RedirectStandardOutput = $true
        RedirectStandardError  = $true
        CreateNoWindow         = $false
    }
    Try {
        $PACLIProcessObject = New-Object System.Diagnostics.Process
        $PACLIProcessObject.StartInfo = $PACLIProcessStartInfo
        $PACLIProcessObject.Start() | Out-Null    
        [PSCustomObject]$Results = @{
            ExitCode = $PACLIProcessObject.ExitCode
            StandardOutput = $PACLIProcessObject.StandardOutput.ReadToEnd()
            StandardError  = $PACLIProcessObject.StandardError.ReadToEnd()
        }
        $WaitForExit = $Global:WaitForExit
        IF ($PACLIProcessObject.WaitForExit($WaitForExit)) {
            If (![string]::IsNullOrEmpty($Results.StandardError)) {
                $Excepetion = [System.Management.Automation.HaltCommandException]::New("Error running PACLI command")
                $Excepetion.Source = $Command
                $Excepetion.Data.Add("StandardOut", $Results.StandardOutput)
                $Excepetion.Data.Add("StandardError", $Results.StandardError)
                Throw $Excepetion
            }
            Return  $Results
        } Else {
            Throw "PACLI Command has run for greater then 600 seconds"
        }
    } finally {
        $PACLIProcessObject.Dispose()
    }
}
#EndRegion '.\Private\PACLI\Invoke-PACLICommand.ps1' 63
#Region '.\Private\Session\Get-SessionToken.ps1' -1


Function Get-SessionToken {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        [Parameter(Mandatory = $false)]
        [string]$AuthType = $script:AuthType,
        [Parameter(Mandatory = $false)]
        [string]$OTP
    )

    $URL_Logon = "$url/api/auth/$AuthType/Logon"

    $sesionBody = @{ 
        username          = $Credentials.username.Replace('\', ''); 
        password          = $Credentials.GetNetworkCredential().password; 
        concurrentSession = "true" 
    } | ConvertTo-Json -Compress
    
    If (![string]::IsNullOrEmpty($RadiusOTP)) {
        $sesionBody.Password += ",$RadiusOTP"
    }

    try {
        $sessionToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $sesionBody
    } catch {
        Write-LogMessage -Type Verbose $PSItem
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($PSItem.Exception.Response.StatusDescription)", $PSItem.Exception))
    } finally {
        $sesionBody = $null
    }

    If ([string]::IsNullOrEmpty($sessionToken)) {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }
    $sessionToken = @{Authorization = $sessionToken }
    return $sessionToken
}
#EndRegion '.\Private\Session\Get-SessionToken.ps1' 41
#Region '.\Private\Session\Invoke-Logoff.ps1' -1

Function Invoke-Logoff {
    param(
        [Parameter(Mandatory = $false)]
        [String]$url = $script:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $script:sessionToken
    )

    $URL_Logoff = $url + "/api/auth/Logoff"
    $null = Invoke-Rest -Uri $URL_Logoff -Header $logonHeader -Command "Post"
}
#EndRegion '.\Private\Session\Invoke-Logoff.ps1' 12
#Region '.\Private\Session\Test-PVWA.ps1' -1

Function Test-PVWA {
    param(
        [Parameter(Mandatory = $true)]
        [String]$PVWAURL
    )

    If (![string]::IsNullOrEmpty($PVWAURL)) {
        If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
            $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
        }
        try {
            # Validate PVWA URL is OK
            Write-LogMessage -Type Debug -MSG "Trying to validate URL: $PVWAURL"
            Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
        } catch [System.Net.WebException] {
            If (![string]::IsNullOrEmpty($PSItem.Exception.Response.StatusCode.Value__)) {
                Write-LogMessage -Type Error -MSG "Received error $($PSItem.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
                Write-LogMessage -Type Error -MSG "Check your connection to PVWA and the PVWA URL"
                Write-LogMessage -Type Verbose $PSItem
                return
            }
        } catch {
            Write-LogMessage -Type Error -MSG "PVWA URL could not be validated"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $PSItem.Exception) -ErrorAction "SilentlyContinue"

        }

    } else {
        Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
        return
    }

}
#EndRegion '.\Private\Session\Test-PVWA.ps1' 34
#Region '.\Private\Usages\Get-Usages.ps1' -1

Function Get-Usages {
    param (

        # The URL of the system to get usages from
        # Used when sessions has not been initalized using preferred method of Initialize-Session
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        # Keywords to be added to the search
        [Parameter(Mandatory = $false)]
        [string]$Keywords,
        # How the results are sorted
        [Parameter(Mandatory = $false)]
        [string]$SortBy,
        # The safe to be searched
        [Parameter(Mandatory = $false)]
        [string]$SafeName,
        # Maximum about of records to return 
        [Parameter(Mandatory = $false)]
        [string]$Limit,
        # Offset to start at 
        [Parameter(Mandatory = $false)]
        [string]$OffSet,
        # Use to limit results to results that starts with
        [Parameter(Mandatory = $false)]
        [boolean]$startswith,
        # Session Token to be used when not already stored in script variable or to allow for a alternate connection
        # Used when sessions has not been initalized using preferred method of Initialize-Session
        [Parameter(Mandatory = $false)]
        [hashtable]$sessionToken = $script:sessionToken

    )

    if ([string]::IsNullOrEmpty($sessionToken)) {
        Write-LogMessage -type Error -MSG "No sessionToken set, run Initialize-Session first"
        Throw [System.Management.Automation.SessionStateException]::New("No sessionToken set, run Initialize-Session first")
       
    }
    Write-LogMessage -Type Debug -Msg "Retrieving Usages..."

    $URL_Usages = "$URL/api/Usages/"

    try {
        $UsagesURLWithFilters = ""
        $UsagesURLWithFilters = $(New-SearchCriteria -sURL $URL_Usages -sSearch $Keywords -sSortParam $SortBy -sSafeName $SafeName -iLimitPage $Limit -iOffsetPage $OffSet -startswith $startswith)
        Write-LogMessage -Type Debug -Msg $UsagesURLWithFilters
    }
    catch {
        Write-LogMessage -Type Error -Msg $_.Exception
    }
    try {
        $GetUsagesResponse = Invoke-Rest -Command Get -Uri $UsagesURLWithFilters -Header $sessionToken
    }
    catch {
        Write-LogMessage -Type Error -Msg $_.Exception.Response.StatusDescription
    }
						
<#     
#v2 Interface with NextLink
    $GetUsagesList = @()
    $counter = 1
    $GetUsagesList += $GetUsagesResponse.Usages | Select-Object UsageID -ExpandProperty Properties 
    Write-LogMessage -Type debug -Msg "Found $($GetUsagesList.count) Usages so far..."
    $nextLink = $("$URL/$($GetUsagesResponse.nextLink)")
    If (![string]::IsNullOrEmpty($GetUsagesResponse.nextLink)) {
        $nextLink = $("$URL/$($GetUsagesResponse.nextLink)")
        Write-LogMessage -Type Debug -Msg "Getting Usages next link: $nextLink"
    }
    else {
        $nextLink = $null
    }
    While (-not [string]::IsNullOrEmpty($nextLink)) {
        $GetUsagesResponse = Invoke-Rest -Command Get -Uri $nextLink -Header $sessionToken
        $GetUsagesList += $GetUsagesResponse.Usages | Select-Object UsageID -ExpandProperty Properties 
        Write-LogMessage -Type info -Msg "Found $($GetUsagesList.count) Usages so far..."
        # Increase the counter
        $counter++
        If (![string]::IsNullOrEmpty($GetUsagesResponse.nextLink)) {
            $nextLink = $("$URL/$($GetUsagesResponse.nextLink)")
            Write-LogMessage -Type Debug -Msg "Getting Usages next link: $nextLink"
        }
        else {
            $nextLink = $null
        }
    } #>

    $GetUsagesList = @()
    $GetUsagesList += $GetUsagesResponse.Usages | Select-Object UsageID -ExpandProperty Properties 
    $totalUsages = $GetUsagesResponse.Total
    
    While ($totalUsages -gt $GetUsagesList.Count) {
        $UsagesURLWithFilters = $(New-SearchCriteria -sURL $URL_Usages -sSearch $Keywords -sSortParam $SortBy -sSafeName $SafeName -iLimitPage $Limit -iOffsetPage $($GetUsagesList.count) -startswith $startswith)
        try {
            $GetUsagesResponse = Invoke-Rest -Command Get -Uri $UsagesURLWithFilters -Header $sessionToken
            $GetUsagesList += $GetUsagesResponse.Usages | Select-Object UsageID -ExpandProperty Properties
            Write-LogMessage -Type debug -Msg "Found $($GetUsagesList.count) Usages so far..."
        }
        catch {
            Write-LogMessage -Type Error -Msg $_.Exception.Response.StatusDescription
        }       
    }	
    Write-LogMessage -Type debug -Msg "Completed retriving $($GetUsagesList.count) Usages"
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: GetUsagesList: $($GetUsagesList |ConvertTo-Json -Depth 9 -Compress)"
    }
    else {
        Write-LogMessage -Type Verbose -Msg "`$GetUsagesList : $($GetUsagesList|ConvertTo-Json -Depth 1)"
    }
    return $GetUsagesList

}
#EndRegion '.\Private\Usages\Get-Usages.ps1' 111
#Region '.\Public\Common\Get-LogFilePath.ps1' -1

Function Get-LogFilePAth{
    return $script:LOG_FILE_PATH
}
#EndRegion '.\Public\Common\Get-LogFilePath.ps1' 4
#Region '.\Public\Common\Initialize-EPVAPIModule.ps1' -1


function Initialize-EPVAPIModule {
    <#
        .SYNOPSIS
        Initializes the Usages Module
        .DESCRIPTION
        Sets the location of PACLI and location to output logs to
        Default log file name is .\EPV-API-Module.Log
    #>
    If ([string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)) {
        $private:ScriptLocation = $pwd.Path
    } else {
        $private:ScriptFullPath = $MyInvocation.MyCommand.Path
        $private:ScriptLocation = Split-Path -Parent $ScriptFullPath
    }
    #$Global:WaitForExit = $(New-TimeSpan -Minutes 30)
    $Global:WaitForExit = 1800000
    $private:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
    $script:LOG_FILE_PATH = "$private:ScriptLocation\EPV-API-Module.Log"
    "Module Loaded at $private:LOG_DATE" | Out-File $script:LOG_FILE_PATH -Append
    $Global:PACLIApp = "$private:ScriptLocation\Pacli.exe"
}
#EndRegion '.\Public\Common\Initialize-EPVAPIModule.ps1' 23
#Region '.\Public\Common\Set-LogFilePath.ps1' -1

function Set-LogfilePath {
        param (
        # Sets the logfile path for the module
        [Parameter(Mandatory)]
        [string]$LogFile,
        # Switch to set LOG_FILE_PATH globally 
        [switch]$global
    )
    If ($global) {
        $global:LOG_FILE_PATH = $LogFile
    } else {
        $script:LOG_FILE_PATH = $LogFile
    }
}
#EndRegion '.\Public\Common\Set-LogFilePath.ps1' 15
#Region '.\Public\PACLI\Get-PACLISessions.ps1' -1

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
#EndRegion '.\Public\PACLI\Get-PACLISessions.ps1' 13
#Region '.\Public\PACLI\Initialize-PACLISession.ps1' -1

Function Initialize-PACLISession {
        <#
        .SYNOPSIS
        Starts PACLI and sets SessionID
        .DESCRIPTION
        Starts PACLI and sets SessionID
        Equivlent to PACLI INIT
    #>
    [CmdletBinding()]
    param (
        # Create a new session instead of using a existing session
        [Parameter()]
        [switch]
        $NewSession,
        # Use a specific value between 1 and 99 as the session ID number
        [ValidateRange(1, 99)]
        [int]
        $PACLISessionID
    )

    If ([string]::IsNullOrEmpty($Global:PACLISessionID) -or (0 -eq $Global:PACLISessionID)) {
        $local:PACLISessionID = $(Get-Random -Minimum 1 -Maximum 100)
        Write-LogMessage -type Debug -Message "No PACLISessionID provided, generated a random ID of $Local:PACLISessionID"
    }    
    IF ([string]::IsNullOrEmpty($global:PACLIApp)) {
        Set-Variable -Scope Global -Name "PACLIApp" -Value ".\Pacli.exe"
        Write-LogMessage -type Debug -Message "No PACLIApp provided, Set PACLIApp to $global:PACLIApp"
    }
    $PACLIProcess = Get-PACLISessions
    If (([string]::IsNullOrEmpty($PACLIProcess) -or (0 -eq $PACLIProcess)) -or $NewSession ) {
        Try {
            $null = Invoke-PACLICommand -Command "init SESSIONID=$local:PACLISessionID" -NoWait
            Write-LogMessage -type Debug -Message "New PALCI session initizaed with a ID of $local:PACLISessionID"
        } catch {
            Throw $_
        }
    } else {
        Write-LogMessage -type Warning -Message "PACLISession already exists. To create a new session use the switch NewSession. Existing PACLI Session IDs: $([string]$PACLIProcess)"
        Continue
    } 

    IF ([string]::IsNullOrEmpty($global:PACLISessionID)) {
        $global:PACLISessionID = $local:PACLISessionID
        Write-LogMessage -type Debug -Message "No global PALCI session ID set, set Global PACLI session ID to $global:PACLISessionID"
    }
    Return $local:PACLISessionID
}





#EndRegion '.\Public\PACLI\Initialize-PACLISession.ps1' 53
#Region '.\Public\PACLI\Invoke-PACLIFileCategoriesList.ps1' -1

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
#EndRegion '.\Public\PACLI\Invoke-PACLIFileCategoriesList.ps1' 39
#Region '.\Public\PACLI\Invoke-PACLIFileCategoryAdd.ps1' -1

Function Invoke-PACLIFileCategoryAdd {
    param (
        # File/Object name of the object
        [Parameter(Mandatory = $true)]
        [string]$Target,
        # Safe that contains the File/Object
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        # SessionID to use
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        # Category to add
        [Parameter(Mandatory = $true)]
        [string]$Catagory,
        # Value to add
        [Parameter(Mandatory = $true)]
        [string]$Value,
        # Suppress results output for successes, errors always returned.
        [Parameter(Mandatory = $false)]
        [switch]$Suppress

    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        SAFE     = $Safe
        FOLDER   = "ROOT"
        FILE     = $Target
        CATEGORY = $Catagory
        VALUE    = $Value
    }
    
    $PACLICommand = "ADDFILECATEGORY $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`" and adding catagory `"$Catagory`" with the value of `"$value`""
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }

}
#EndRegion '.\Public\PACLI\Invoke-PACLIFileCategoryAdd.ps1' 44
#Region '.\Public\PACLI\Invoke-PACLIFileCategoryDelete.ps1' -1

Function Invoke-PACLIFileCategoryDelete {
    param (

        # File/Object name of the object
        [Parameter(Mandatory = $true)]
        [string]$Target,
        # Safe that contains the File/Object
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        # SessionID to use
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        # Category to delete
        [Parameter(Mandatory = $true)]
        [string]$Catagory,
        # Suppress results output for successes, errors always returned.
        [Parameter(Mandatory = $false)]
        [switch]$Suppress
    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        SAFE     = $Safe
        FOLDER   = "ROOT"
        FILE     = $Target
        CATEGORY = $Catagory
    }
    
    $PACLICommand = "DELETEFILECATEGORY  $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID

    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`" and deleting catagory `"$Catagory`""
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }
}
#EndRegion '.\Public\PACLI\Invoke-PACLIFileCategoryDelete.ps1' 40
#Region '.\Public\PACLI\Invoke-PACLIFileCategoryUpdate.ps1' -1

Function Invoke-PACLIFileCategoryUpdate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [Parameter(Mandatory = $true)]
        [string]$Catagory,
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $false)]
        [switch]$Suppress
    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        SAFE     = $Safe
        FOLDER   = "ROOT"
        FILE     = $Target
        CATEGORY = $Catagory
        VALUE    = $Value
    }
    
    $PACLICommand = "UPDATEFILECATEGORY $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID

    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`"  and updating catagory `"$Catagory`" with the value of `"$value`""
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }
}
#EndRegion '.\Public\PACLI\Invoke-PACLIFileCategoryUpdate.ps1' 37
#Region '.\Public\PACLI\Invoke-PACLIFileDelete.ps1' -1

Function Invoke-PACLIFileDelete {
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
    $PACLICommand = "DELETEFILE $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    } Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        } else {
            Throw $PSItem
        }
    }
    $PACLIcmdOrdDir.Add("Status", "Deleted")
    $Result.StandardOutput | ConvertFrom-Csv -Header Name, Value| ForEach-Object { $PACLIcmdOrdDir.Add($psitem.Name, $psitem.Value, "Deleted") }
    return [PSCustomObject]$PACLIcmdOrdDir 
}
#EndRegion '.\Public\PACLI\Invoke-PACLIFileDelete.ps1' 30
#Region '.\Public\PACLI\Invoke-PACLIFileFind.ps1' -1

Function Invoke-PACLIFileFind {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INCLUDE_DELETED_WITH_ACCESSMARKS", "INCLUDE_DELETED", "ONLY_DELETED", "WITHOUT_DELETED")]
        [String]$DelOption = "INCLUDE_DELETED_WITH_ACCESSMARKS"
    )
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        Safe   = $Safe
        Folder = "ROOT"
    }
    $PACLICommand = "FINDFILES $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir) DELETEDOPTION=$DelOption output`(ALL,ENCLOSE`)"
    Try {
        $Result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    } Catch [System.Management.Automation.HaltCommandException] {
        If ($PSItem.Exception.Data.StandardError -match "ITATS053E Object .* doesn't exist.") { 
            throw [System.IO.FileNotFoundException]::New()
        } else {
            Throw $PSItem
        }
    }
    if ([string]::IsNullOrEmpty($result.StandardOutput)) {
        Write-LogMessage -type Info -MSG "No Results found"
        return ""
    }
    $headers = @( "Name", "Accessed", "Creation Date", "Created By", "Deletion Date", "Deleted By",
        "Last Used Date", "Last Used By", "Lock Date", "Locked By", "Locked By Gw", "Size", "History", "
    Internalname", "Safe", "Folder", "File ID", "Locked By User Id", "Validation Status", "Human Creation Date",
        "Human Created By", "Human Last Used Date", "Human Last Used By", "Human Last Retrieved By Date", "
    Human Last Retrieved By", "Component Creation Date", "Component Created By", "Component Last Used Date",
        "Component Last Used By", "Component Last Retrieved Date", "Component Last Retrieved By", "File Categories")
    $Cleaned = $Result.StandardOutput | ConvertFrom-Csv -Header $headers       
    return [PSCustomObject]$Cleaned
}
#EndRegion '.\Public\PACLI\Invoke-PACLIFileFind.ps1' 39
#Region '.\Public\PACLI\Invoke-PACLIFileList.ps1' -1

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
    $PACLICommand = "FILESLIST $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir) output`(ALL,ENCLOSE`)"
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
#EndRegion '.\Public\PACLI\Invoke-PACLIFileList.ps1' 27
#Region '.\Public\PACLI\Invoke-PACLIFileUndelete.ps1' -1

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
#EndRegion '.\Public\PACLI\Invoke-PACLIFileUndelete.ps1' 33
#Region '.\Public\PACLI\Invoke-PACLISafeClose.ps1' -1

Function Invoke-PACLISafeClose {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [switch]$Suppress
    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID

    $PACLICommand = "CLOSESAFE SAFE=`"$Safe`""

    Try {
        $null = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
        IF ($Safe -in $Script:OpenSafeList) {
            $Script:OpenSafeList.remove($safe)
        }
    } Catch {
        If (![string]::IsNullOrEmpty($PSItem.Exception.data.StandardError)) {
            If ($PSItem.Exception.data.StandardError -notmatch "ITATS023E") {
                Write-LogMessage -type Error -MSG "Error while closing safe `"$safe`""
                return
            }
        }
    }
    If (!$Suppress) {
        $output =[PSCustomObject]@{
            Safe = $safe
            Open = "No"
        }
        $output | Format-Table
    }
}
#EndRegion '.\Public\PACLI\Invoke-PACLISafeClose.ps1' 35
#Region '.\Public\PACLI\Invoke-PACLISafeOpen.ps1' -1

Function Invoke-PACLISafeOpen {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [switch]$Suppress
    )
    Write-LogMessage -type Debug -msg "Current Open Safe List: $Script:OpenSafeList"
    IF (!(Test-Path variable:Script:OpenSafeList)) {
        [System.Collections.ArrayList]$Script:OpenSafeList = @()
    }
    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLICommand = "OPENSAFE SAFE=`"$Safe`" output`(ENCLOSE,NAME,STATUS,SAFEID`)"

    Try {
        $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
        IF ($Safe -notin $Script:OpenSafeList) {
            $Script:OpenSafeList += $safe
        } 
    } Catch {
        If (![string]::IsNullOrEmpty($PSItem.Exception.data.StandardError)) {
            Write-LogMessage -type Debug -MSG "Error Message: $($PSItem.Exception.data.StandardError)"
            Write-LogMessage -type Error -MSG "Error while opening safe `"$safe`""
            return
        } 
    }
    If (!$Suppress) {
        $result.StandardOutput  | ConvertFrom-Csv -Header "Safe","Open","SafeID" | Format-Table
    }
}
#EndRegion '.\Public\PACLI\Invoke-PACLISafeOpen.ps1' 32
#Region '.\Public\PACLI\Invoke-PACLISessionLogoff.ps1' -1

Function Invoke-PACLISessionLogoff{
            <#
        .SYNOPSIS
        Using PACLI logs off the target vault and terminates the PACLI process
        .DESCRIPTION
        PUsing PACLI logs off the target vault and terminates the PACLI process
    #>
    param (
        [int]$PACLISessionID
    )
    $PACLIProcess = Get-PACLISessions
    Try {
        Invoke-Expression "$global:PACLIApp  logoff SESSIONID=$local:PACLIProcess"
        Invoke-Expression "$global:PACLIApp  term SESSIONID=$local:PACLIProcess"
    } Catch {
        $PSItem.ErrorDetails
    }
    [System.Collections.ArrayList]$Script:OpenSafeList = @()
}
#EndRegion '.\Public\PACLI\Invoke-PACLISessionLogoff.ps1' 20
#Region '.\Public\PACLI\Invoke-PACLISessionLogon.ps1' -1

Function Invoke-PACLISessionLogon {

            <#
        .SYNOPSIS
        Using PACLI logs onto the target vault and set defaults
        .DESCRIPTION
        Using PACLI logs onto the target vault and set defaults
        Equivlent to running the following commands
        PACLI Define
        PACLI Default
        PACLI Logon
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$vaultIP,
        [Parameter(Mandatory = $false)]
        [pscredential]$Credentials,
        [int]$PACLISessionID
    )
    $PACLIProcess = Get-PACLISessions
    If ([string]::IsNullOrEmpty($PACLIProcess)) {
        Initialize-PACLISession
    }
    

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID

    while (($Credentials.password.Length -eq 0) -or [string]::IsNullOrEmpty($Credentials.username)) {
        $Credentials = Get-Credential
        If ($null -eq $Credentials) { return
        }
    }
    Try {
        Invoke-PACLICommand -Command "define vault=`"PCALI$local:PACLISessionID`" address=`"$vaultIP`"" | Out-Null
        Invoke-PACLICommand -Command "default vault=`"PCALI$local:PACLISessionID`" user=`"$($Credentials.username)`" folder=`"Root`"" | Out-Null
        [string]$resultLogon = Invoke-PACLICommand -Command "logon password=$($Credentials.GetNetworkCredential().password)" | Out-Null
        if (![string]::IsNullOrEmpty($resultLogon)) {
            $resultLogon
            Invoke-PACLICommand -Command "logoff SESSIONID=$local:PACLISessionID"
            Invoke-PACLICommand -Command "term SESSIONID=$local:PACLISessionID"
            Write-LogMessage -type Error "Error During logon, PACLI Session Terminated"
            continue
        }
    } Catch {
        $PSItem.ErrorDetails

    }
    [System.Collections.ArrayList]$Script:OpenSafeList = @()
}
#EndRegion '.\Public\PACLI\Invoke-PACLISessionLogon.ps1' 50
#Region '.\Public\PACLI\Invoke-PACLIStorePasswordObject.ps1' -1

Function Invoke-PACLIStorePasswordObject {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $false)]
        [string]$PACLISessionID,
        [Parameter(Mandatory = $false)]
        [switch]$Suppress

    )

    $Local:PACLISessionID = Get-PACLISessionParameter -PACLISessionID $PACLISessionID
    $PACLIcmdOrdDir = [ordered]@{
        SAFE     = $Safe
        FOLDER   = "ROOT"
        FILE     = $Target
        PASSWORD = ""
    }
    
    $PACLICommand = "STOREPASSWORDOBJECT $(Format-PACLICommand -cmdOrdDir $PACLIcmdOrdDir)"
    $result = Invoke-PACLICommand -Command $PACLICommand -PACLISessionID $Local:PACLISessionID
    If (![string]::IsNullOrEmpty($result.StandardError)) {
        Write-LogMessage -type Error -MSG "Error while working with file `"$target`" in safe `"$safe`" and storing password object"
        return
    }
    If (!$Suppress) {
        Invoke-PACLIFileCategoriesList -Safe $safe -Target $Target
    }

}
#EndRegion '.\Public\PACLI\Invoke-PACLIStorePasswordObject.ps1' 33
#Region '.\Public\PACLI\Remove-PACLISession.ps1' -1

Function Remove-PACLISession {

        <#
        .SYNOPSIS
        Removes active PACLISessions
        .DESCRIPTION
        Removes active PACLISessions
        Equivlent to running PACLI TERM
    #>
    param (
        # SessionID to terminate
        [int]$PACLISessionID,
        # Remove all active PACLI Sessions
        [switch]$RemoveAllSessions
    )
    Function RemoveSession {
        param (
            [int]$PACLISessionID
        )
            $null = Invoke-Expression "`"$global:PACLIApp`" term SESSIONID=$PACLISessionID"
            Write-LogMessage -type Info "PACLI session $PACLISessionID removed successful"
    }

    Function RemoveAllSessions {
        $sessions = Get-PACLISessions
        If (![string]::IsNullOrEmpty($sessions)){

        $sessions | ForEach-Object { Invoke-PACLICommand -Command "term" -PACLISessionID $PSItem }
        }
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
        Write-LogMessage -type Info "All PACLI session removed successful and global scope cleared"
    }

    If ($RemoveAllSessions) {
        Write-LogMessage -type Info "Removing all PACLI sessions"
        $null = RemoveAllSessions
    } Elseif (![string]::IsNullOrEmpty($PACLISessionID)) {
        Write-LogMessage -type Info "Removing provided PACLI session $PACLISessionID"
        $null = RemoveSession -PACLISessionID $PACLISessionID
    } Else {
        Write-LogMessage -type Info "Removing global PACLI session $PACLISessionID"
        $null = RemoveSession -PACLISessionID $Global:PACLISessionID
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
    }
}
#EndRegion '.\Public\PACLI\Remove-PACLISession.ps1' 46
#Region '.\Public\PACLI\Set-PACLISession.ps1' -1

Function Set-PACLISession{
    param (
        [Parameter()]
        [int]
        $PACLISessionID
    )
    $Global:PACLISessionID = $PACLISessionID
}
#EndRegion '.\Public\PACLI\Set-PACLISession.ps1' 9
#Region '.\Public\PACLI\Test-PACLISession.ps1' -1

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
#EndRegion '.\Public\PACLI\Test-PACLISession.ps1' 20
#Region '.\Public\Sessions\Close-Session.ps1' -1

Function Close-Session {
    Initialize-Function
    Invoke-Logoff -url $PVWAURL -logonHeader $Token -ErrorAction SilentlyContinue
}
#EndRegion '.\Public\Sessions\Close-Session.ps1' 5
#Region '.\Public\Sessions\Initialize-Session.ps1' -1

function Initialize-Session {

    <#
        .SYNOPSIS
        Connects to the source PVWA
        .DESCRIPTION
        Connects to the source PVWA and tests the connection to ensure the supplied credentials/LogonToken are working
    #>
    [CmdletBinding()]
    param (
        # URL for the environment
        #- HTTPS://Destination.lab.local/PasswordVault
    
        [Parameter(Mandatory = $false)]
        [Alias("URL")]
        [String]$PVWAURL,
        # Authentication types for logon.
        # - Available values: _CyberArk, LDAP, RADIUS_
        # - Default value: _CyberArk_
        [Parameter(Mandatory = $false)]
        [ValidateSet("cyberark", "ldap", "radius")]
        [String]$AuthType = "cyberark",
        #One Time Password for use with RADIUS
        [Parameter(Mandatory = $false)]
        $otp,
        # Credentials for source environment
        [Parameter(Mandatory = $false)]
        [PSCredential]$PVWACredentials,
        # Headers for use with environment
        # - Used with Privileged Cloud environment
        # - When used, log off is suppressed in the environment
        [Parameter(Mandatory = $false)]
        $logonToken,
        # Use this switch to Disable SSL verification (NOT RECOMMENDED)
        [Parameter(Mandatory = $false)]
        [Switch]$DisableSSLVerify
    )
    Initialize-Function
    Test-PVWA -PVWAURL $PVWAURL
    If (![string]::IsNullOrEmpty($logonToken)) {
        Write-LogMessage -Type Info -MSG "Setting Logon Token"
        if ($logonToken.GetType().name -eq "String") {
            $logonHeader = @{Authorization = $logonToken }
            Set-Variable -Scope Script -Name sessionToken -Value $logonHeader -Force   
        } else {
            Set-Variable -Scope Script -Name sessionToken -Value $logonToken -Force
        }
    } else {
        If ([string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
        } 
        New-Variable -Name AuthType -Value $AuthType -Scope Script -Force

        New-Variable -Scope script -Name sessionToken -Value $(Get-SessionToken -Credentials $PVWACredentials -AuthType $AuthType -URL $PVWAURL -OTP $OTP) -Force

        If ($null -eq $script:sessionToken) {
            Write-LogMessage -Type Error -MSG "No sessionToken generated" -Footer
            return 
        }
    }

    New-Variable -Scope script -Name PVWAURL -Value $PVWAURL -Force
    if (Test-Session -sessionToken $script:sessionToken -url $script:PVWAURL) {
        Write-LogMessage -type Info -MSG "Session successfully configured and tested"
        Write-LogMessage -type Debug -MSG "Token set to $($script:sessionToken |ConvertTo-Json -Depth 10)"
    } else {
        Write-LogMessage -type Error -MSG "Session failed to connect successfully"
    }
}
#EndRegion '.\Public\Sessions\Initialize-Session.ps1' 70
#Region '.\Public\Sessions\Test-Session.ps1' -1

Function Test-Session {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param(
        $sessionToken,
        $url
    )
    Function Invoke-Report {
        Write-LogMessage -type Debug -MSG "Error Message attempting to do admin connection: $($RestErrorAdmin.ErrorRecord)"
        IF ([string]::IsNullOrEmpty(!$($RestErrorUser))) {
            Write-LogMessage -type Debug -MSG "Error Message attempting to do user connection: $($RestErrorUser.ErrorRecord)"
        }
    }

    $URL_GetHealthSummery = "$url/API/ComponentsMonitoringSummary/"
    Try {
        $ReturnResultAdmin = Invoke-RestMethod -Method Get -Uri $URL_GetHealthSummery -Headers $sessionToken -ErrorVariable RestErrorAdmin
        Write-LogMessage -Type Verbose -MSG "Test-Session:ReturnResult: $($ReturnResultAdmin|ConvertTo-Json -Depth 9 -Compress)"
        if ((![string]::IsNullOrEmpty($ReturnResultAdmin.Components)) -and ($ReturnResultAdmin.Components.Count -ne 0)) {
            Return $true
        } else {
            Invoke-Report
            return $false
        }
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($PSitem.Exception.Response.StatusCode -eq "Forbidden") {
            $URL_Verify = "$url/API/Verify/"
            $ReturnResultUser = Invoke-RestMethod -Method Get -Uri $URL_Verify -Headers $sessionToken -ErrorVariable RestErrorUser
            IF ([string]::IsNullOrEmpty($ReturnResultUser.ServerName) -or [string]::IsNullOrEmpty(!$RestErrorUser)) {
                Invoke-Report
                Return $false
            } else {
                Invoke-Report
                Write-LogMessage -type Warning -MSG "Connected with a account that is not a member of `"vault admins`". Access to create may be restricted."
                Return $true
            }
        }
    }
}
#EndRegion '.\Public\Sessions\Test-Session.ps1' 40
#Region '.\Public\Usages\Clear-Usagelist.ps1' -1

Function Clear-Usagelist {
    Remove-Variable -Scope Script -Name UsageList -ErrorAction SilentlyContinue
}
#EndRegion '.\Public\Usages\Clear-Usagelist.ps1' 4
#Region '.\Public\Usages\Export-Usageslist.ps1' -1


Function Export-Usageslist {
    <#
        .SYNOPSIS
        Exports usages from target
        .DESCRIPTION
        Exports the usages from the target environment using REST API (undocumented)
        Creates CSV file to allow for easy review and import
    #>
    param (
        # File name of the CSV file created
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $exportCSV = ".\ExportOfUsages.csv",

        # URL of PVWA. Must include "/PasswordVault"
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        # Keywords to search by
        # How keywords are searched is controlled by "WideAccountsSearch" and values present in "Search Properties"
        [Parameter(Mandatory = $false)]
        [string]$Keywords,
        # Property to sort results by (Ineffective on exports)
        [Parameter(Mandatory = $false)]
        [string]$SortBy,
        # Name of Safe to Export From
        [Parameter(Mandatory = $false)]
        [string]$SafeName,
        # Limit of accounts to return. 
        # Maximum is controlled via MaxDisplayedRecords
        [Parameter(Mandatory = $false)]
        [string]$Limit,
        # Limit Keyword searches to "StartsWith" instead of default "Contains"
        [Parameter(Mandatory = $false)]
        [boolean]$startswith,
        # PACLI SessionID to use
        [Parameter(Mandatory = $false)]
        [hashtable]$sessionToken
    )
    $excludeProp = @("exportCSV")
    $parms = $PSBoundParameters | Where-Object Values -NE $null | Where-Object Keys -NotIn $excludeProp
    Write-LogMessage -Type Info -Msg "Starting export of usages"

    If ([string]::IsNullOrEmpty($parms)) {
        $usages = Get-Usages
    } else {
        $usages = Get-Usages @parms
    }
    Write-LogMessage -Type Info -Msg "Found $($usages.count) usages"
    Write-LogMessage -Type Info -Msg "Starting export to CSV of $($usages.count) usages"
    $usages = $usages | Where-Object { $PSItem.Safe -notIn $objectSafesToRemove }
    [string[]]$usageProperties = $usages | ForEach-Object { $PSItem.PSObject.Properties.Name } | Select-Object -Unique | Sort-Object
    [string[]]$outputProperties = @("Safe", "MasterPassName", "MasterPassFolder", "PolicyID", "Name", "Username", "Address", "UsageID", "Folder") + $usageProperties | Select-Object -Unique
    $usages | Select-Object $outputProperties | Sort-Object -Property "Safe", "PolicyID", "MasterPassName", "Name" | Export-Csv $exportCSV
    Write-LogMessage -Type Info -Msg "Export of $($usages.count) usages completed."
    New-Variable -Force -Scope Script -Name UsagesList -Value $usages
}
#EndRegion '.\Public\Usages\Export-Usageslist.ps1' 59
#Region '.\Public\Usages\Get-Usageslist.ps1' -1

Function Get-Usageslist {
        <#
        .SYNOPSIS
        Returns a PSCustomObject of the usages that are in memory
        .DESCRIPTION
        Returns a PSCustomObject of the usages that are in memory
        Loaded via Export-UsagesList or Import-UsagesList
    #>

    return $script:UsagesList
}
#EndRegion '.\Public\Usages\Get-Usageslist.ps1' 12
#Region '.\Public\Usages\Import-Usages.ps1' -1

Function Import-Usagelist {
    param (
        <#
    Path and filename for use by Export
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
        [ValidatePattern('\.csv$')]
        $importCSV = ".\ExportOfUsages.csv"
    )
    [array]$script:UsagesList = Import-Csv $importCSV -ErrorAction SilentlyContinue
    Write-LogMessage -Type Info -Msg "Imported $($script:UsagesList.count) accounts from `"$importCSV`""
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: Imported Usages: $($script:UsagesList |ConvertTo-Json -Depth 9 -Compress)"
    }
}
#EndRegion '.\Public\Usages\Import-Usages.ps1' 17
#Region '.\Public\Usages\Import-Usageslist.ps1' -1

Function Import-Usageslist {
    <#
        .SYNOPSIS
        Imports the CSV of usages
        .DESCRIPTION
        Imports the CSV of usages
        Use Export-Usagelist to create a CSV file for review. Once review and any modifications / removals is completed of that file import using this command. Allows for targeted testing.  
        #>
    param (
        # Path and filename for use by Export
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$importCSV = ".\ExportOfUsages.csv"
    )
    [array]$script:UsagesList = Import-Csv $importCSV -ErrorAction SilentlyContinue
    Write-LogMessage -Type Info -Msg "Imported $($script:UsagesList.count) accounts from `"$importCSV`""
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: Imported Usages: $($script:UsagesList |ConvertTo-Json -Depth 9 -Compress)"
    }
}
#EndRegion '.\Public\Usages\Import-Usageslist.ps1' 22
#Region '.\Public\Usages\New-UsagePacli.ps1' -1

Function New-UsagePacli {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        Using the PSCustomObject array passed, creates the usages in target vault via PACLI
        .DESCRIPTION
        Using the PSCustomObject array passed, creates or modifies existing usages in target vault via PACLI
        Single threaded process
        Object requires the minimun of the following properties:
            Name, UsageID, UsageInfo, Safe, Folder, File
        Any additional properties will be added
        .NOTES
        If a usage was deleted, but a version still exists in the safe, the prior version will be restored and then updated.
        #>
    param(
        # The object to be processed.

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $SourceObject,
        [switch]
        $suppress
    )
    begin {
        $global:InDebug = $PSBoundParameters.Debug.IsPresent
        $global:InVerbose = $PSBoundParameters.Verbose.IsPresent
    }

    PROcess {
        $fail = $false
        [PSCustomObject]$failArray = @{}

        switch ($SourceObject) {
        ([string]::IsNullOrEmpty($SourceObject.Safe)) { throw [System.ArgumentNullException]::New("Missing Safe Name") 
            }
        ([string]::IsNullOrEmpty($SourceObject.Folder)) { throw [System.ArgumentNullException]::New("Missing Folder Name") 
            }
        ([string]::IsNullOrEmpty($SourceObject.File)) { throw [System.ArgumentNullException]::New("Missing File Name") 
            }
        } 

        [string[]]$nullProps = ($SourceObject | Get-Member -MemberType NoteProperty | Where-Object { ([String]::IsNullOrEmpty($SourceObject.$($PSItem.Name))) }).Name
        $SourceObject = $SourceObject | Select-Object -ExcludeProperty $nullProps
        
        $excludeProp = @("Name", "UsageID", "UsageInfo", "Safe", "Folder", "File") 
        Write-LogMessage -type Verbose -MSG "Excluding the following properties: $excludeProp"
        $Source = $SourceObject | Select-Object -ExcludeProperty $excludeProp

        Try {
            IF ($($SourceObject.Safe) -notin $Script:OpenSafeList) {
                Invoke-PACLISafeOpen -Safe $($SourceObject.Safe) -Suppress:$suppress
            }
            Try {
                Write-LogMessage -type Debug -MSG "Getting file catagories from `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                $targetObject = Invoke-PACLIFileCategoriesList -Safe $($SourceObject.Safe) -Target $($SourceObject.Name)
            } Catch [System.IO.FileNotFoundException] {
                Write-LogMessage -type Debug -MSG "Object not found, creating object `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                $targetObject = Invoke-PACLIStorePasswordObject -Safe $($SourceObject.Safe) -Target $($SourceObject.Name)
            }

            $target = $targetObject | Select-Object -ExcludeProperty $excludeProp
            Write-LogMessage -type debug -MSG "Result of exclusions on target: $target"

            [PSCustomObject]$difFileCat = Compare-Stuff -ReferenceObject $Source -DifferenceObject $target -namesOnly
            If ([string]::IsNullOrEmpty($Target)) {
                [string[]]$addFileCatResult = $($Source.PSObject.Properties.Name)
                Write-LogMessage -type debug -MSG "No file catagories found on target `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
            } else {
                $addFileCatResult = (Compare-Stuff -ReferenceObject $($target.PSObject.Properties.Name) -DifferenceObject $($Source.PSObject.Properties.Name)).value
            }
            Write-LogMessage -type debug -MSG "The following file catagories need to be added to `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`": $($addFileCatResult |Where-Object {$Psitem -notin $difFileCat})"
            Write-LogMessage -type debug -MSG "The following file catagories do not match on `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`": $($($difFileCat| Where-Object {$psitem.Property -notin $addFileCatResult}).Property)"

            $difFileCat | ForEach-Object { Try {
                    If ($PSItem.Property -in $addFileCatResult) {
                        Invoke-PACLIFileCategoryAdd -Target $($targetObject.File) -Safe $($targetObject.Safe) -Catagory $($PSitem.Property) -Value $($PSitem.Value) -Suppress
                        Write-LogMessage -type debug -MSG "Added catagory `"$($PSitem.Property)`" with the value of `"$($PSitem.Value)`" on target `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                    } else {
                        Invoke-PACLIFileCategoryUpdate -Target $($targetObject.File) -Safe $($targetObject.Safe) -Catagory $($PSitem.Property) -Value $($PSitem.Value) -Suppress
                        Write-LogMessage -type debug -MSG "Updated catagory `"$($PSitem.Property)`" with the value of `"$($PSitem.Value)`" on target `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                    }  
                } Catch [System.Management.Automation.HaltCommandException] {
                    Write-LogMessage -type Error -MSG "Error while running PACLI Command"
                    Write-LogMessage -Type Error -MSG "Command run: `"$($PSItem.Exception.Source)`"" 
                    Write-LogMessage -Type Error -MSG "StandardError: `"$($PSItem.Exception.Data.StandardError)`""
                    $script:fail = $True
                    return
                } Catch {
                    Write-LogMessage -type Error -MSG "Error while running Sync-UsageToPacli"
                    Write-LogMessage -Type Error -msg $PSItem
                    $script:fail = $True
                    $failArray += [PSCustomObject]$psitem
                    return
                }
            }
            If ($fail) {
                Write-LogMessage -type Error -Msg "Creation of objects experienced Errors"
                Write-LogMessage -type Error -Msg $failArray
            } elseif (!$suppress) {
                Write-LogMessage -type Info -Msg "Creation of object `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`" completed succesfully"
                $SourceObject
            } Else {
                Write-LogMessage -type Debug -Msg "Creation of object `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`" completed succesfully"
            }
        } Catch [System.Management.Automation.HaltCommandException] {
            Write-LogMessage -type Error -MSG "Error while running PACLI Command"
            Write-LogMessage -Type Error -MSG "Command run: `"$($PSItem.Exception.Source)`"" 
            Write-LogMessage -Type Error -MSG "StandardError: `"$($PSItem.Exception.Data.StandardError)`""
        } Catch {
            Write-LogMessage -type Error -MSG "Error while running New-UsagePacli"
            Write-LogMessage -Type Error -msg $PSItem
        }
    }
    End {
    }
}
#EndRegion '.\Public\Usages\New-UsagePacli.ps1' 117
#Region '.\Public\Usages\Sync-UsageToPacli.ps1' -1

Function Sync-UsageToPacli {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        Using the PSCustomObject array passed, creates the usages in target vault via PACLI
        .DESCRIPTION
        Using the PSCustomObject array passed, creates or modifies existing usages in target vault via PACLI
        Single threaded process
        Object requires the minimun of the following properties:
            Name, UsageID, UsageInfo, Safe, Folder, File
        Any additional properties will be added
        .NOTES
        If a usage was deleted, but a version still exists in the safe, the prior version will be restored and then updated.
        #>
    param(
        # The object to be processed.

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $SourceObject,
        [switch]
        $suppress
    )
# Kept in place for backwards compatibility
return New-UsagePACLI -SourceObject $SourceObject -Suppress $suppress

}
#EndRegion '.\Public\Usages\Sync-UsageToPacli.ps1' 28
