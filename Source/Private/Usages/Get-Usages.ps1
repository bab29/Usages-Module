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
