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
    $Global:WaitForExit = $(New-TimeSpan -Minutes 30)
    $Global:WaitForExit = 1800000
    $private:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
    $script:LOG_FILE_PATH = "$private:ScriptLocation\EPV-API-Module.Log"
    "Module Loaded at $private:LOG_DATE" | Out-File $script:LOG_FILE_PATH -Append
    $Global:PACLIApp = "$private:ScriptLocation\Pacli.exe"
}