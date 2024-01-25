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