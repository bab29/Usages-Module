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