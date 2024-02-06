function Initialize-EPVAPIModule {

    If ([string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)) {
        $private:ScriptLocation = $pwd.Path
    } else {
        $private:ScriptFullPath = $MyInvocation.MyCommand.Path
        $private:ScriptLocation = Split-Path -Parent $ScriptFullPath
    }
    $private:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
    $script:LOG_FILE_PATH = "$private:ScriptLocation\EPV-API-Module.Log"
    "Module Loaded at $private:LOG_DATE" | Out-File $script:LOG_FILE_PATH -Append
    $Global:PACLIApp = "$private:ScriptLocation\Pacli.exe"


}