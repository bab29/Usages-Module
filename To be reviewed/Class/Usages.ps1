Class Usage {
[string]$AccountDiscoveryDate
[string]$Address
[string]$CreationMethod
[string]$DeviceType
[string]$DiscoveryPlatformType
[string]$Folder
[string]$MasterPassFolder
[string]$MasterPassName
[string]$name
[string]$PolicyID
[string]$safe
[string]$ServiceName
[string]$UsageInfo
[hashtable]$platformUsageProperties


hidden [pscustomobject]$conversion
hidden [string[]]$ExcludePropertiesGen
hidden [string[]]$ExcludePropertiesSecret
hidden [string[]]$ExcludePropertiesRemote

Usage(){
    $this.conversion = @{
        PolicyID = "platformId"
    }
    $this.ExcludePropertiesGen = @("id", "AccountDiscoveryDate", "CreationMethod", "createdTime", "categoryModificationTime")
    $this.ExcludePropertiesSecret = @()
    $this.ExcludePropertiesRemote = @()
    $this.platformUsageProperties = @{}
}



}