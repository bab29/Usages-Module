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