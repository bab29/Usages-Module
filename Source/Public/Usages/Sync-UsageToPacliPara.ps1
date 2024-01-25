Function Sync-UsageToPacliPara {
    param(
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
        
    }
    End {
    }
}