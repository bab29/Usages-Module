Class secretManagement {
    
    [nullable[bool]]$automaticManagementEnabled = $null
    [string]$manualManagementReason
    [string]$status
    [string]$lastModifiedTime
    [string]$lastReconciledTime
    [string]$lastVerifiedTime
}

Class remoteMachinesAccess {
    [string]$remoteMachines
    [AllowEmptyString()]
    [nullable[bool]]$accessRestrictedToRemoteMachines = $null
}

Class Account {
    [string]$ID
    [string]$Safe
    [string]$name
    [string]$address
    [string]$userName
    [string]$platformId
    [string]$safeName
    [string]$secretType
    [string]$secret
    [pscustomobject]$platformAccountProperties
    [secretManagement]$secretManagement
    [remoteMachinesAccess]$remoteMachinesAccess
    [string]$createdTime
    [string]$categoryModificationTime
    [string]$deletionTime

    hidden [pscustomobject]$conversion
    hidden [string[]]$ExcludePropertiesGen
    hidden [string[]]$ExcludePropertiesSecret
    hidden [string[]]$ExcludePropertiesRemote

    account() {
        $this.platformAccountProperties = @{}
        $this.secretManagement = New-Object -type secretManagement
        $this.remoteMachinesAccess = New-Object -type remoteMachinesAccess
        $this.secretType = "password"
        $this.conversion = @{
            PolicyID = "platformId"
        }
        $this.ExcludePropertiesGen = @("id", "secret", "lastModifiedTime", "createdTime", "categoryModificationTime")
        $this.ExcludePropertiesSecret = @()
        $this.ExcludePropertiesRemote = @()
    }

    load($object) {
        
        $generalProps = $This | Get-Member -MemberType Property | Select-Object -Property Name
        $secretProps = $This.secretManagement.GetType() | Get-Member -MemberType Property | Select-Object -Property Name
        $remoteProps = $This.remoteMachinesAccess | Get-Member -MemberType Property | Select-Object -Property Name
        $object.keys | ForEach-Object {
            If ($psitem -in $generalProps.Name) {   
                $this.$($PSItem) = $object[$psitem]
            } elseif ($psitem -in $secretProps.name) {   
                $this.secretManagement.$($PSItem) = $object[$psitem]
            } elseif ($psitem -in $remoteProps.name) {   
                $this.remoteMachinesAccess.$($PSItem) = $object[$psitem]
            } else { 
                IF ($null -eq $this.platformAccountProperties.$PSitem) {  
                    $this.platformAccountProperties.add($($PSItem), $object[$psitem])
                } else {
                    $this.platformAccountProperties.$PSitem = $object[$psitem]
                }
            }
        }
    }

    load($object, [bool]$convertFromV1) {
        $ConvertedOobject = @{}
        if ($convertFromV1) {
            $object.keys | ForEach-Object { If ($null -ne $this.conversion[$PSitem]) {
                    $ConvertedOobject.add($($this.conversion[$PSitem]), $object[$psitem])
                } Else {
                    $ConvertedOobject.add($($PSItem), $object[$psitem])
                }
            }
        } else {
            $ConvertedOobject = $object
        }
        $this.load($ConvertedOobject)
    }

    [PSCustomObject]RemoveNull() {
        $generalPropsNonNull = $this.psobject.Properties | Where-Object {$null -ne $PSItem.value} | Select-Object -Property Name
        $secretPropsNonNull = $this.secretManagement.psobject.Properties | Where-Object {$null -ne $PSItem.value} | Select-Object -Property Name
        $remotePropsNonNull = $this.remoteMachinesAccess.psobject.Properties | Where-Object {$null -ne $PSItem.value} | Select-Object -Property Name

        $resultObject = [string[]]@{}
        $resultObject = $this | Select-Object -Property $generalPropsNonNull.Name
        if ($secretPropsNonNull.count -ne 0) {
            $resultObject.secretManagement = $this.secretManagement | Select-Object -Property $secretPropsNonNull.Name 
        } else {
            $resultObject.secretManagement = $null
            $this.ExcludePropertiesGen += "secretManagement"
        }
        if ($remotePropsNonNull.count -ne 0) {
            $resultObject.remoteMachinesAccess = $this.remoteMachinesAccess | Select-Object -Property $remotePropsNonNull.Name 
            $resultObject.remoteMachinesAccess = $null
            $this.ExcludePropertiesGen += "remoteMachinesAccess"
        }
        $resultObject = $resultObject | Select-Object -Property $generalPropsNonNull.Name
        Return $resultObject
    }

    [PSCustomObject]RemoveExcluded() {
        $generalPropsNonNull = $this.psobject.Properties | Where-Object {$null -ne $PSItem.value} | Select-Object -Property Name
        $secretPropsNonNull = $this.secretManagement.psobject.Properties | Where-Object {$null -ne $PSItem.value} | Select-Object -Property Name
        $remotePropsNonNull = $this.remoteMachinesAccess.psobject.Properties | Where-Object {$null -ne $PSItem.value} | Select-Object -Property Name

        $resultObject = [string[]]@{}
        $resultObject = $this | Select-Object -Property $generalPropsNonNull.Name
        if ($secretPropsNonNull.count -ne 0) {
            $resultObject.secretManagement = $this.secretManagement | Select-Object -Property $secretPropsNonNull.Name -ExcludeProperty $this.ExcludePropertiesSecret
        } else {
            $resultObject.secretManagement = $null
            $this.ExcludePropertiesGen += "secretManagement"
        }
        if ($remotePropsNonNull.count -ne 0) {
            $resultObject.remoteMachinesAccess = $this.remoteMachinesAccess | Select-Object -Property $remotePropsNonNull.Name -ExcludeProperty $this.ExcludePropertiesRemote
        } else {
            $resultObject.remoteMachinesAccess = $null
            $this.ExcludePropertiesGen += "remoteMachinesAccess"
        }
        $resultObject = $resultObject | Select-Object -Property $generalPropsNonNull.Name -ExcludeProperty $this.ExcludePropertiesGen
        Return $resultObject
    }

    [string]ConvertToJson () {
        Return $($this.RemoveNull() | ConvertTo-Json)
    }
    [string]ConvertToJson ([bool]$AllValues) {
        Return $($this.RemoveNull() | ConvertTo-Json)
    }
}
