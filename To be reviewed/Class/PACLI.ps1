Class PACLI {
    [string]$SessionID
    [string]$vaultIP
    hidden [string]$Vault = "PACLI"
    [string]$PACLIApp = ".\Pacli.exe"
    hidden [string]$noSessionMsg = "No session found"
    
    NewSession() {
        Try {
            $PACLIProcess = $this.GetSession()
            If (!([string]::IsNullOrEmpty($PACLIProcess))) {
                $PACLIProcess.CommandLine -match '(?:SESSIONID=)(?<sessionid>\d\d)' | Out-Null
                Invoke-Expression "$($This.PACLIApp) term SESSIONID=$($Matches.sessionid)"
            }
            Set-Variable -Scope Global -Name "PACLISessionID" -Value $(Get-Random -Maximum 100)
            $this.SESSIONID = $Global:PACLISessionID
            Invoke-Expression "$($This.PACLIApp) init SESSIONID=$Global:PACLISessionID"
        
        } Catch {
            $This.RemoveSession()
            Throw "Error during New Session"
        }
    }
    ReuseSession() {
        Try {
            $sessionTest = $this.GetSessionID()
            If ($This.noSessionMsg -eq $sessionTest ) {
                Throw [System.Management.Automation.SessionStateException]::New()
            } else {
                $this.TestSession()
                $this.SESSIONID = $Global:PACLISessionID
            }
        } catch {
            Throw $_
        }
    }
    TestSession() {
        $testSafe = "vaultinternal"
        $test = Invoke-Expression "$($This.PACLIApp) opensafe safe=`"$testSafe`"  output``(name``) SESSIONID=$Global:PACLISessionID"
        If ($testsafe -eq $test) {
            Invoke-Expression " $($This.PACLIApp) closesafe safe=`"$testSafe`" SESSIONID=$Global:PACLISessionID"
            Write-LogMessage -type Info "PACLI test successful"
        } else {
            $This.RemoveSession()
            Throw "Error Opening Test Safe, PACLISession terminated: $_"
        }
    }
    RemoveAllSessions() {
        $sessions = $this.GetSessionID()
        $sessions | ForEach-Object { Invoke-Expression "$($This.PACLIApp) term SESSIONID=$PSItem" }
        $this.SessionID = $null
        Remove-Variable -Scope Global -Name "PACLISessionID" -ErrorAction SilentlyContinue
        Write-LogMessage -type Info "All PACLI session removed successful and global scope cleared"
    }
    RemoveSession() {
        IF ($null -ne $this.SessionID) {
            Invoke-Expression "$($This.PACLIApp) term SESSIONID=$($this.SessionID)"
            $this.SessionID = $null
            Write-LogMessage -type Info "PACLI session $($this.SessionID) removed successful"
        } Else { 
            Write-LogMessage -type Info $This.noSessionMsg
        }
    }
    [System.Diagnostics.Process[]]GetSession() {
        Return $(Get-Process -Name "PACLI" -ErrorAction SilentlyContinue)
    }
    [String[]]GetSessionID() {
        $sessions = $this.GetSession()
        $matchesArray = $sessions | ForEach-Object { $($PSItem).CommandLine -match '(?:SESSIONID=)(?<sessionid>\b([0-9]|[1-9][0-9]|100)\b)' | Out-Null; $Matches.SessionID }
        IF ([string]::IsNullOrEmpty($matchesArray)) {
            Return $This.noSessionMsg
        } else {
            Return [string[]]$($matchesArray)
        }
    }
    LogonSession () {
        $this.vaultIP = Read-Host -Prompt "Please enter vault address"
        $this.LogonSession($this.vaultIP)
    }
    LogonSession ([string]$vaultIP) {
        $Credentials = Get-Credential
        IF (($Credentials.password.Length -eq 0) -or [string]::IsNullOrEmpty($Credentials.username)) {
            return
        }
        $this.LogonSession($vaultIP, $Credentials)
    }
    LogonSession (
        [string]$vaultIP,
        [pscredential]$Credentials
    ) {
        IF (([string]::IsNullOrEmpty($This.SessionID)) -or ([string]::IsNullOrEmpty($this.GetSession()))) {
            $this.NewSession()
        }
        Invoke-Expression "$($This.PACLIApp) define vault=`"$($this.Vault)`" address=`"$vaultIP`" SESSIONID=$Global:PACLISessionID"
        Invoke-Expression "$($This.PACLIApp) default vault=`"$($this.Vault)`" user=`"$($Credentials.username)`" folder=`"Root`" SESSIONID=$Global:PACLISessionID"
        [string]$resultLogon = Invoke-Expression "$($This.PACLIApp) logon password=$($Credentials.GetNetworkCredential().password) SESSIONID=$Global:PACLISessionID 2>&1"
        if (![string]::IsNullOrEmpty($resultLogon)) {
            $this.RemoveSession()
            Write-LogMessage -type Error "Error During logon, PACLI Session Terminated"
            Write-LogMessage -type Verbose -msg $resultLogon
            continue
        }
    }

}
class PACLIObject :  PACLI   {
    [string]$Safe
    [string]$Folder
    [string]$Name
    hidden [PACLICommand[]]$commands
    
    [PSCustomObject]OpenSafe([string]$safe) {
        $This.Safe = $safe
        Return $($this.OpenSafe())
    }
    [PSCustomObject]OpenSafe() {
        $this.Action = "OPENSAFE"
        $this.TargetType = $null
        $this.Target = $null
        $this.output = "ENCLOSE,NAME,STATUS,SAFEID"
        $this.commandGUID = "$($this.Action) SAFE=`"$($this.safe)`" output($($this.output))"
        Return $($this.Execute())
    }
    [PSCustomObject]CloseSafe([string]$safe) {
        $This.Safe = $safe
        Return $($this.CloseSafe())
    }
    [PSCustomObject]CloseSafe() {
        $this.Action = "CLOSESAFE"
        $this.TargetType = $null
        $this.Target = $null
        $this.commandGUID = "$($this.Action) SAFE=`"$($this.safe)`""
        Return $($this.Execute())
    }
    [PSCustomObject[]]Run() {
        $results = $this.commands | ForEach-Object { $PSitem.Run() }
        Return $results 
    }
}

class PACLICommand : PACLI {
    [string]$Action
    [string]$TargetType
    [string]$Target
    [string]$Catagory
    [string]$Value
    [string]$Output
    hidden [string]$OutputOverride
    hidden [string]$Command
    hidden [PSCustomObject]$LastResult
    hidden [bool]$OutputAllowed
    hidden [guid]$commandGUID

    hidden [String[]]$enableCat = @()
    hidden [String[]]$enableVal = @()
    hidden [String[]]$enableOutput = @() 

    PACLICommand() {
        NewSession
        $this.SessionID = $this.GetSessionID()[0]
        $this.commandGUID = [guid]::NewGuid().ToString()
    }

    hidden CheckRequired () {
        $Missing = @{}
        IF ([string]::IsNullOrEmpty($this.action)) {
            $Missing += "Action"
        } 
        IF ([string]::IsNullOrEmpty($this.TargetType)) {
            $Missing += "TargetType"
        }
        IF ([string]::IsNullOrEmpty($this.Target)) {
            $Missing += "Target"
        } 
        IF ([string]::IsNullOrEmpty($Missing)) {
            Throw "The following minimun required items are missing: $missing"
        }  
        $this.Command = "$($this.Action) $($this.TargetType)=`"$($This.Target)`""
        if (!([string]::IsNullOrEmpty($this.safe))) {
            $this.Command = "$($this.Command) SAFE=`"$($this.safe)`""
        } else {
            Write-LogMessage -type Debug -MSG "No value set for Safe, assuming PACLI default set"
        }
        if (!([string]::IsNullOrEmpty($this.Folder))) {
            $this.Command = "$($this.Command) FOLDER=`"$($this.Folder)`""
        } else {
            Write-LogMessage -type Debug -MSG "No value set for Folder, assuming PACLI default set"
        }
    }

    hidden BuildCommand () {
        $This.CheckRequired()
    }
    hidden [PSCustomObject]Execute() {
        Start-Process -FilePath $($This.PACLIApp) -NoNewWindow -Wait -ArgumentList @($this.Command) -RedirectStandardOutput "$($this.commandGUIDGUID)-Out" -RedirectStandardError "$($this.commandGUIDGUID)-Error"
        $outputFile = Get-Content ".\$($this.commandGUIDGUID)-Out"
        $errorFile = Get-Content ".\$($this.commandGUIDGUID)-Error"
        [PSCustomObject]$Results = @{
            StandardOutput = $outputFile
            StandardError  = $errorFile 
        }
        Remove-Item -Force -Path ".\$($this.commandGUIDGUID)-Out"
        Remove-Item -Force -Path ".\$($this.commandGUIDGUID)-Error"
        $this.LastResult = $Results
        Return  $Results
    }

    [PSCustomObject]Run() {
        Try {
            $this.BuildCommand()
            if (!($this.SessionID -match '\b([0-9]|[1-9][0-9]|100)\b')) {
                $this.ReuseSession()
            }   
            If (($this.SessionID -match '\b([0-9]|[1-9][0-9]|100)\b')) {
                $this.Command = "$($this.Command) SESSIONID=$($this.SessionID)" 
            }
            Return $this.Execute() 
        } catch [System.Management.Automation.SessionStateException] {
            Write-LogMessage -type Error -MSG "$($This.noSessionMsg). Start a new session using NewSession"
            Return $null
        } catch {
            Throw "Error during PACLI Command: $($this.Command)"
        }
    }

}

class PACLIFileCat : PACLI, PACLICommand {
    hidden [PACLICommand[]]$PACLIFileCatCMD
    hidden $commandToRun

    hidden [String[]]$enableCat = @("ADDFILECATEGORY", "UPDATEFILECATEGORY", "DELETEFILECATEGORY", `
            "LISTFILECATEGORIES", "ADDSAFEFILECATEGORY", "UPDATESAFEFILECATEGORY", "DELETESAFEFILECATEGORY", `
            "LISTSAFEFILECATEGORIES")
    hidden [String[]]$enableVal = @("ADDFILECATEGORY", "UPDATEFILECATEGORY")
    hidden [String[]]$enableOutput = @("LISTFILECATEGORIES", "OPENSAFE") 
    
    hidden BuildCommand () {
        $This.CheckRequired()
        If ($This.action -in $this.enableCat) {
            if (!([string]::IsNullOrEmpty($this.Catagory))) {
                $this.commandToRun = "$($this.commandToRun) CATEGORY=`"$($this.Catagory)`""
            }
        } else {
            $this.Catagory = $null
        }
        If ($This.action -in $this.enableVal) {
            if (!([string]::IsNullOrEmpty($this.VALUE))) {
                $this.commandToRun = "$($this.commandToRun) VALUE=`"$($this.Value)`""
            }
        } else {
            $this.Value = $null
        }
        if ($This.action -in $this.enableOutput) {
            if (!([string]::IsNullOrEmpty($this.OutputOverride))) {
                $this.commandToRun = "$($this.commandToRun) output($($this.OutputOverride))"
            } elseif (!([string]::IsNullOrEmpty($this.output))) {
                $this.commandToRun = "$($this.commandToRun) output($($this.output))"
            }
        } else {
            $This.Output = $null
        }
    }
    [PSCustomObject]GetFileCats ([string]$object, [string]$safe) {
        $This.Safe = $safe
        Return $($this.GetFileCats($object))
    }
    [PSCustomObject]GetFileCats (
        [string]$object
    ) {
        $this.Target = $object
        Return $($this.GetFileCats())
    }
    [PSCustomObject]GetFileCats (
    ) {
        $this.Action = "LISTFILECATEGORIES"
        $this.TargetType = "File"
        $this.output = "ENCLOSE,CATEGORYNAME,CATEGORYVALUE"
        $this.OutputAllowed = $true
        $this.Run()
        $testingwork = $this.ConvertFileCat($this.LastResult.StandardOutput)
        return $testingwork
    }

    [PSCustomObject]ConvertFileCat($object) {
        $Work = [ordered]@{}
        $work.Add("Safe", $this.Safe)
        $work.Add("Folder", $this.Folder)
        $work.Add("Name", $this.Target)
        $object | ConvertFrom-Csv -Header Name, Value | ForEach-Object { $work.Add($psitem.Name, $psitem.Value) }
        return $Work 
    }


    AddFileCats ([string]$safe, [string]$object, [string]$Catagory, [string]$value) {
        $this.safe = $safe
        $($this.AddFileCats($object, $Catagory, $value))
    }
    AddFileCats ([string]$object, [string]$Catagory, [string]$value) {
        $this.Target = $object
        $($this.AddFileCats($Catagory, $value))
    }
    AddFileCats (
        [string]$Catagory,
        [string]$value
    ) {
        $this.Action = "ADDFILECATEGORY"
        $this.TargetType = "File"
        $this.Catagory = $Catagory
        $this.Value = $value
        
    }
    UpdateFileCats([string]$Safe, [string]$object, [string]$Catagory, [string]$value) {
        $this.safe = $Safe
        $($this.UpdateFileCats($object, $Catagory, $value))
    }
    UpdateFileCats (
        [string]$object,
        [string]$Catagory,
        [string]$value
    ) {
        $this.Target = $object
        $($this.UpdateFileCats($Catagory, $value))
    }
    UpdateFileCats (
        [string]$Catagory,
        [string]$value
    ) {
        $this.Action = "UPDATEFILECATEGORY"
        $this.TargetType = "File"
        $this.Catagory = $Catagory
        $this.Value = $value
    }


}

