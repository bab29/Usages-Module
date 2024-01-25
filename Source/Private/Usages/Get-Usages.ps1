Function Get-Usages {
    param (
        [Parameter(Mandatory = $false)]
        [string]$url = $script:PVWAURL,
        [Parameter(Mandatory = $false)]
        [string]$Keywords,
        [Parameter(Mandatory = $false)]
        [string]$SortBy,
        [Parameter(Mandatory = $false)]
        [string]$SafeName,
        [Parameter(Mandatory = $false)]
        [string]$Limit,
        [Parameter(Mandatory = $false)]
        [boolean]$startswith,
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
        $UsagesURLWithFilters = $(New-SearchCriteria -sURL $URL_Usages -sSearch $Keywords -sSortParam $SortBy -sSafeName $SafeName -iLimitPage $Limit -startswith $startswith)
        Write-LogMessage -Type Debug -Msg $UsagesURLWithFilters
    } catch {
        Write-LogMessage -Type Error -Msg $_.Exception
    }
    try {
        $GetUsagesResponse = Invoke-Rest -Command Get -Uri $UsagesURLWithFilters -Header $sessionToken
    } catch {
        Write-LogMessage -Type Error -Msg $_.Exception.Response.StatusDescription
    }
						
    $GetUsagesList = @()
    $counter = 1
    $GetUsagesList += $GetUsagesResponse.Usages | Select-Object UsageID -ExpandProperty Properties 
    Write-LogMessage -Type debug -Msg "Found $($GetUsagesList.count) Usages so far..."
    $nextLink = $("$URL/$($GetUsagesResponse.nextLink)")
    If (![string]::IsNullOrEmpty($GetUsagesResponse.nextLink)) {
        $nextLink = $("$URL/$($GetUsagesResponse.nextLink)")
        Write-LogMessage -Type Debug -Msg "Getting Usages next link: $nextLink"
    } else {
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
        } else {
            $nextLink = $null
        }
    }
				
    Write-LogMessage -Type debug -Msg "Completed retriving $($GetUsagesList.count) Usages"
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: GetUsagesList: $($GetUsagesList |ConvertTo-Json -Depth 9 -Compress)"
    } else {
        Write-LogMessage -Type Verbose -Msg "`$GetUsagesList : $($GetUsagesList|ConvertTo-Json -Depth 1)"
    }

    return $GetUsagesList

}
