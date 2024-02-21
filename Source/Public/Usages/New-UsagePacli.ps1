Function New-UsagePacli {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        Using the PSCustomObject array passed, creates the usages in target vault via PACLI
        .DESCRIPTION
        Using the PSCustomObject array passed, creates or modifies existing usages in target vault via PACLI
        Single threaded process
        Object requires the minimun of the following properties:
            Name, UsageID, UsageInfo, Safe, Folder, File
        Any additional properties will be added
        .NOTES
        If a usage was deleted, but a version still exists in the safe, the prior version will be restored and then updated.
        #>
    param(
        # The object to be processed.

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
        $fail = $false
        [PSCustomObject]$failArray = @{}

        switch ($SourceObject) {
        ([string]::IsNullOrEmpty($SourceObject.Safe)) { throw [System.ArgumentNullException]::New("Missing Safe Name") 
            }
        ([string]::IsNullOrEmpty($SourceObject.Folder)) { throw [System.ArgumentNullException]::New("Missing Folder Name") 
            }
        ([string]::IsNullOrEmpty($SourceObject.File)) { throw [System.ArgumentNullException]::New("Missing File Name") 
            }
        } 

        [string[]]$nullProps = ($SourceObject | Get-Member -MemberType NoteProperty | Where-Object { ([String]::IsNullOrEmpty($SourceObject.$($PSItem.Name))) }).Name
        $SourceObject = $SourceObject | Select-Object -ExcludeProperty $nullProps
        
        $excludeProp = @("Name", "UsageID", "UsageInfo", "Safe", "Folder", "File") 
        Write-LogMessage -type Verbose -MSG "Excluding the following properties: $excludeProp"
        $Source = $SourceObject | Select-Object -ExcludeProperty $excludeProp

        Try {
            IF ($($SourceObject.Safe) -notin $Script:OpenSafeList) {
                Invoke-PACLISafeOpen -Safe $($SourceObject.Safe) -Suppress:$suppress
            }
            Try {
                Write-LogMessage -type Debug -MSG "Getting file catagories from `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                $targetObject = Invoke-PACLIFileCategoriesList -Safe $($SourceObject.Safe) -Target $($SourceObject.Name)
            } Catch [System.IO.FileNotFoundException] {
                Write-LogMessage -type Debug -MSG "Object not found, creating object `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                $targetObject = Invoke-PACLIStorePasswordObject -Safe $($SourceObject.Safe) -Target $($SourceObject.Name)
            }

            $target = $targetObject | Select-Object -ExcludeProperty $excludeProp
            Write-LogMessage -type debug -MSG "Result of exclusions on target: $target"

            [PSCustomObject]$difFileCat = Compare-Stuff -ReferenceObject $Source -DifferenceObject $target -namesOnly
            If ([string]::IsNullOrEmpty($Target)) {
                [string[]]$addFileCatResult = $($Source.PSObject.Properties.Name)
                Write-LogMessage -type debug -MSG "No file catagories found on target `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
            } else {
                $addFileCatResult = (Compare-Stuff -ReferenceObject $($target.PSObject.Properties.Name) -DifferenceObject $($Source.PSObject.Properties.Name)).value
            }
            Write-LogMessage -type debug -MSG "The following file catagories need to be added to `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`": $($addFileCatResult |Where-Object {$Psitem -notin $difFileCat})"
            Write-LogMessage -type debug -MSG "The following file catagories do not match on `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`": $($($difFileCat| Where-Object {$psitem.Property -notin $addFileCatResult}).Property)"

            $difFileCat | ForEach-Object { Try {
                    If ($PSItem.Property -in $addFileCatResult) {
                        Invoke-PACLIFileCategoryAdd -Target $($targetObject.File) -Safe $($targetObject.Safe) -Catagory $($PSitem.Property) -Value $($PSitem.Value) -Suppress
                        Write-LogMessage -type debug -MSG "Added catagory `"$($PSitem.Property)`" with the value of `"$($PSitem.Value)`" on target `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                    } else {
                        Invoke-PACLIFileCategoryUpdate -Target $($targetObject.File) -Safe $($targetObject.Safe) -Catagory $($PSitem.Property) -Value $($PSitem.Value) -Suppress
                        Write-LogMessage -type debug -MSG "Updated catagory `"$($PSitem.Property)`" with the value of `"$($PSitem.Value)`" on target `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`""
                    }  
                } Catch [System.Management.Automation.HaltCommandException] {
                    Write-LogMessage -type Error -MSG "Error while running PACLI Command"
                    Write-LogMessage -Type Error -MSG "Command run: `"$($PSItem.Exception.Source)`"" 
                    Write-LogMessage -Type Error -MSG "StandardError: `"$($PSItem.Exception.Data.StandardError)`""
                    $script:fail = $True
                    return
                } Catch {
                    Write-LogMessage -type Error -MSG "Error while running Sync-UsageToPacli"
                    Write-LogMessage -Type Error -msg $PSItem
                    $script:fail = $True
                    $failArray += [PSCustomObject]$psitem
                    return
                }
            }
            If ($fail) {
                Write-LogMessage -type Error -Msg "Creation of objects experienced Errors"
                Write-LogMessage -type Error -Msg $failArray
            } elseif (!$suppress) {
                Write-LogMessage -type Info -Msg "Creation of object `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`" completed succesfully"
                $SourceObject
            } Else {
                Write-LogMessage -type Debug -Msg "Creation of object `"$($SourceObject.Name)`" in safe `"$($SourceObject.Safe)`" completed succesfully"
            }
        } Catch [System.Management.Automation.HaltCommandException] {
            Write-LogMessage -type Error -MSG "Error while running PACLI Command"
            Write-LogMessage -Type Error -MSG "Command run: `"$($PSItem.Exception.Source)`"" 
            Write-LogMessage -Type Error -MSG "StandardError: `"$($PSItem.Exception.Data.StandardError)`""
        } Catch {
            Write-LogMessage -type Error -MSG "Error while running New-UsagePacli"
            Write-LogMessage -Type Error -msg $PSItem
        }
    }
    End {
    }
}