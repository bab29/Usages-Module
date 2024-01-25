function Set-LogfilePath {
        param (
        #Sets the logfile path for the module
        [Parameter(Mandatory)]
        [string]$LogFile,
        [switch]$global
    )
    If ($global) {
        $global:LOG_FILE_PATH = $LogFile
    } else {
        $script:LOG_FILE_PATH = $LogFile
    }
}