function Compare-Stuff {
    [CmdletBinding()]
    param (
        $ReferenceObject, 
        $DifferenceObject, 
        $MaxDepth = -1, 
        [switch]$IncludeEqual, 
        [switch]$ExcludeDifferent, 
        [switch]$PassThru, 
        [switch]$Compact,
        [switch]$namesOnly,
        [parameter(DontShow)]
        $__Property, 
        [parameter(DontShow)]
        $__Depth = 0 
    )

    # Parameter help description
 
    if ($MaxDepth -eq -1 -or $__Depth -le $MaxDepth) {
        #check for arrays of PSCustomObjects or arrays of custom class and iterate over those
        if (($ReferenceObject -is [array]) -and ($ReferenceObject[0] -is [PSCustomObject] -or $null -eq $ReferenceObject[0].GetType().Namespace)) {
            $__Depth++
            for ($i = 0; $i -lt $ReferenceObject.Count; $i++) {
                #recurse carrying the current Property name + index and Depth values forward
                Compare-Stuff $ReferenceObject[$i] $DifferenceObject[$i] -__Property ($__Property + "[$i]") -__Depth $__Depth -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru -Compact:$Compact -namesOnly:$namesOnly
            }
        }
        #check for custom classes or PSCutomObjects and iterate over their properties.
        elseif ($ReferenceObject -is [PSCustomObject] -or $null -eq $ReferenceObject.GetType().Namespace) {
            $__Depth++
            foreach ($prop in $ReferenceObject.PSObject.properties.name) {
                #build up the property name hiarachry
                $newProp = $prop
                if ($__Property) {
                    $newProp = $__Property + '.' + $prop
                }
                # handle ref. or diff. objects equal null
                $refValue = $ReferenceObject.$prop
                $diffValue = $DifferenceObject.$prop
                if ($Null -eq $refValue) {
                    $refValue = ''
                }
                if ($null -eq $diffValue) {
                    $diffValue = ''
                }
                #recurse carrying the current Property and Depth values forward
                Compare-Stuff $refValue $diffValue -__Property $newProp -__Depth $__Depth -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru -Compact:$Compact -namesOnly:$namesOnly
            }
        } else {
            #if we reach here we are dealing with a scalar or array of scalars that the built-in cmdlet can already deal with
            $output = Compare-Object $ReferenceObject $DifferenceObject -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru |
                Select-Object @{n = 'Property'; e = { $__Property } }, @{n = 'Value'; e = { $_.InputObject } }, SideIndicator
            if ($Compact) {
                $output | Group-Object Property, { $_.SideIndicator -eq '==' } | ForEach-Object {
                    if ($_.Group[0].SideIndicator -eq '==') {
                        [PSCustomObject][Ordered]@{
                            Property        = $_.Group.Property
                            ReferenceValue  = $_.Group.Value
                            DifferenceValue = $_.Group.Value
                        }
                    } else {
                        [PSCustomObject][Ordered]@{
                            Property        = $_.Group[0].Property
                            ReferenceValue  = ($_.Group.where{ $_.SideIndicator -eq '<=' }).Value
                            DifferenceValue = ($_.Group.where{ $_.SideIndicator -eq '=>' }).Value
                        }
                    }
                }
            } elseif ($namesOnly) {
                $output | Where-Object -Property SideIndicator -eq "<="| Select-Object -Property Property,Value -Unique 
            } Else {
                $output
            }
        }
    }
}