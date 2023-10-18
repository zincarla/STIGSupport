#region CKL functions
<#
.SYNOPSIS
    Gets a stig info attribute

.DESCRIPTION
    Gets a stig info attribute, literally value of a "SI_DATA" under the "STIG_INFO" elements from the XML data of the CKL. This contains general information on the STIG file itself. (Version, Date, Name)

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER Attribute
    The Attribute you wish to query.
  
.EXAMPLE
    Get-StigInfoAttribute -CKLData $CKLData -Attribute "Version"
#>
function Get-StigInfoAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true,ValueFromPipeline = $true)][XML]$CKLData,
        [Parameter(Mandatory=$true)]$Attribute
    )
    #What we will return
    $ToReturn = $null
    #If vuln was set
    if ($Attribute -ne $null )
    {
        #Grab attribute by VulnID
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//SI_DATA[SID_NAME='$Attribute']").Node.SID_DATA
    }
    else
    {
        #We need one or the other
        Write-Error "Attribute must be set!"
    }
    #Write error if the attribute was not found
    if ($ToReturn -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found"
    }
    return $ToReturn
}

<#
.SYNOPSIS
    Gets general info from the checklist (Release, Title, Description)

.PARAMETER CKLData
    CKL data as loaded from the Import-StigCKL
  
.EXAMPLE
    Get-CheckListInfo -CKLData $CKLData
#>
function Get-CheckListInfo {
    Param([Alias("XMLData")][Parameter(Mandatory=$true,ValueFromPipeline = $true)][XML]$CKLData)
    return (New-Object -TypeName PSObject -Property @{Title=(Get-StigInfoAttribute -CKLData $CKLData -Attribute "title");
                                                      Description=(Get-StigInfoAttribute -CKLData $CKLData -Attribute "description");
                                                      Release=(Get-StigInfoAttribute -CKLData $CKLData -Attribute "releaseinfo");
                                                      ID=(Get-StigInfoAttribute -CKLData $CKLData -Attribute "stigid")});
}

<#
.SYNOPSIS
    Gets a vuln's informational attribute

.DESCRIPTION
    Gets a vuln's info attribute, literally "ATTRIBUTE_DATA" from the requested "STIG_DATA" element in the XML data of the CKL. This gets information on a specific vuln (Fix text, severity, title)

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to query

.PARAMETER RuleID
    Rule_ID of the Vuln to query

.PARAMETER Attribute
    The Attribute you wish to query.
  
.EXAMPLE
    Get-VulnInfoAttribute -CKLData $CKLData -Attribute "Version"
#>
function Get-VulnInfoAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null,
        $RuleID=$null, 
        [Parameter(Mandatory=$true)]
        [ValidateSet("Vuln_Num",
            "Severity",
            "Group_Title",
            "Rule_ID",
            "Rule_Ver",
            "Rule_Title",
            "Vuln_Discuss",
            "IA_Controls",
            "Check_Content",
            "Fix_Text",
            "False_Positives",
            "False_Negatives",
            "Documentable",
            "Mitigations",
            "Potential_Impact",
            "Third_Party_Tools",
            "Mitigation_Control",
            "Responsibility",
            "Security_Override_Guidance",
            "Check_Content_Ref",
            "Class",
            "STIGRef",
            "TargetKey",
            "CCI_REF")]
        $Attribute
    )
    #What we will return
    $ToReturn = $null
    #If vuln was set
    if ($VulnID -ne $null )
    {
        #Grab attribute by VulnID
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
    }
    elseif ($RuleID -ne $null)
    {
        #If rule was set, grab it by the rule
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
        if ($ToReturn -eq $null) {
            $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
        }
    }
    else
    {
        #We need one or the other
        Write-Error "VulnID or RuleID must be set!"
    }
    #Write error if the attribute was not found
    if ($ToReturn -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found for $($VulnID)$RuleID"
    }
    #Return the result
    return $ToReturn
}

<#
.SYNOPSIS
    Sets a vuln's informational attribute

.DESCRIPTION
    Sets a vuln's info attribute, literally "ATTRIBUTE_DATA" from the requested "STIG_DATA" element in the XML data of the CKL. This gets information on a specific vuln (Fix text, severity, title)

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to set

.PARAMETER RuleID
    Rule_ID of the Vuln to set

.PARAMETER Attribute
    The Attribute you wish to set

.PARAMETER Value
    The value to set the Attribute to
  
.EXAMPLE
    Set-VulnInfoAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "Fix_Text" -Value "To fix this..."
#>
function Set-VulnInfoAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, 
        $VulnID=$null, 
        $RuleID=$null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Vuln_Num",
            "Severity",
            "Group_Title",
            "Rule_ID",
            "Rule_Ver",
            "Rule_Title",
            "Vuln_Discuss",
            "IA_Controls",
            "Check_Content",
            "Fix_Text",
            "False_Positives",
            "False_Negatives",
            "Documentable",
            "Mitigations",
            "Potential_Impact",
            "Third_Party_Tools",
            "Mitigation_Control",
            "Responsibility",
            "Security_Override_Guidance",
            "Check_Content_Ref",
            "Class",
            "STIGRef",
            "TargetKey",
            "CCI_REF")]
        $Attribute, 
        [Parameter(Mandatory=$true)][string]$Value
    )
    #The attribute to set
    $ToSet = $null
    if ($VulnID -ne $null)
    {
        #If we have VulnID, set the attribute by that
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.STIG_DATA |
            Where-Object {$_.VULN_ATTRIBUTE -eq $Attribute}
    }
    elseif ($RuleID -ne $null)
    {
        #If we have rule id, set it by that
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.STIG_DATA |
            Where-Object {$_.VULN_ATTRIBUTE -eq $Attribute}
        if ($ToSet -eq $null) {
            $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.STIG_DATA |
            Where-Object {$_.VULN_ATTRIBUTE -eq $Attribute}
        }
    }
    else
    {
        #We need Vuln or Rule ID
        Write-Error "VulnID or RuleID must be set!"
    }
    #Set the value if we found it
    if ($ToSet)
    {
        $ToSet.ATTRIBUTE_DATA = $Value
    }
    else
    {
        #Or write error if the attribute was not found
        Write-Error "Specified attribute ($Attribute) was not found for $($VulnID)$RuleID"
    }
}

<#
.SYNOPSIS
    Gets a vuln's finding attribute (Status, Comments, Details, etc)

.DESCRIPTION
    Gets a stig's vuln attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to get

.PARAMETER RuleID
    Rule_ID of the Vuln to get

.PARAMETER Attribute
    The Attribute you wish to get
  
.EXAMPLE
    Get-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS"
#>
function Get-VulnFindingAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null,
        $RuleID=$null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("SEVERITY_JUSTIFICATION",
            "SEVERITY_OVERRIDE",
            "COMMENTS",
            "FINDING_DETAILS",
            "STATUS")]
        $Attribute
    )
    #Value to return
    $ToReturn = $null
    if ($VulnID -ne $null)
    {
        #If we have vulnid get property that way
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.$Attribute
    }
    elseif ($RuleID -ne $null)
    {
        #If we have ruleid, get property that way
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.$Attribute
        if ($ToReturn -eq $null) {
            $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.$Attribute
        }
    }
    else
    {
        #We need either Vuln or Rule ID
        Write-Error "VulnID or RuleID must be set!"
    }
    #If to return is null, write error as someone messed up
    if ($ToReturn -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found for $($VulnID)$RuleID"
    }
    #return value
    return $ToReturn
}

<#
.SYNOPSIS
    Sets a vuln's finding attribute (Status, Comments, Details, etc)

.DESCRIPTION
    Sets a stig's vuln attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to Set

.PARAMETER RuleID
    Rule_ID of the Vuln to Set

.PARAMETER Attribute
    The Attribute you wish to Set

.PARAMETER Value
    The new value for the Attribute
  
.EXAMPLE
    Set-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS" -Value "This was checked by script"
#>
function Set-VulnFindingAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null,
        $RuleID=$null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("SEVERITY_JUSTIFICATION",
            "SEVERITY_OVERRIDE",
            "COMMENTS",
            "FINDING_DETAILS",
            "STATUS")]
        $Attribute,
        [Parameter(Mandatory=$true)][string]$Value
    )
    #Attribute to set
    $ToSet = $null
    if ($VulnID -ne $null)
    {
        #If we have vuln get attribute to set by it
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode
    }
    elseif ($RuleID -ne $null)
    {
        #If we have rule get attribute to set by it
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode
        if ($ToSet -eq $null) {
            $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode
        }
    }
    #If we found the element to set
    if ($ToSet)
    {
        #Set it
        $ToSet.$Attribute = $Value
        return $true
    }
    else
    {
        #Otherwise error out
        Write-Error "Vuln $VulnID$RuleID not found!"
    }
    return $false
}

<#
.SYNOPSIS
    Returns all VulnIDs contained in the CKL

.PARAMETER CKLData
    Data as return from the Import-StigCKL
  
.EXAMPLE
    Get-VulnIDs -CKLData $CKLData
#>
function Get-VulnIDs
{
    Param([Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData)
    #Return an array of all VulnIDs
    $ToReturn = @()+(Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']").Node.ATTRIBUTE_DATA
    return $ToReturn
}

<#
.SYNOPSIS
    Returns an array of all the names of the attributes contained in the CKL for each STIG (FIX_Text, Check_Content, etc)

.DESCRIPTION
    This is a helper function more for use in updating the StigSupport module.

.PARAMETER CKLData
    Data as return from the Import-StigCKL
  
.EXAMPLE
    Get-VulnAttributeList -CKLData $CKLData
#>
function Get-VulnAttributeList
{
    Param([Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData)
    #Get and return all vuln attributes
    return $CKLData.CHECKLIST.STIGS.iSTIG.VULN.STIG_Data.VULN_ATTRIBUTE | Sort-Object | Select-Object -Unique
}

<#
.SYNOPSIS
    Sets the findings information for a single vuln

.DESCRIPTION
    This is one of the main tools in this module, this will set the result for a given vuln to what you specify

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to Set

.PARAMETER RuleID
    Rule_ID of the Vuln to Set

.PARAMETER Details
    Finding details

.PARAMETER Comments
    Finding comments

.PARAMETER Result
    Final Result (Open, Not_Reviewed, or NotAFinding)
  
.EXAMPLE
    Set-VulnCheckResult -CKLData $CKLData -VulnID "V-11111" -Details "Not set correctly" -Comments "Checked by xyz" -Result Open
#>
function Set-VulnCheckResult
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null, 
        $RuleID=$null,
        [Alias("Finding")]$Details=$null, 
        $Comments=$null,
        [Alias("Status")][Parameter(Mandatory=$true)][ValidateSet("Open","NotAFinding","Not_Reviewed", "Not_Applicable")]$Result
    )
    #If we have what we need
    if ($VulnID -ne $null -or $RuleID -ne $null)
    {
        if ($Result -ne $null)
        {
            $Res = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "STATUS" -Value $Result
            if (-not $Res){Write-Warning ("Failed to write: status of vuln "+$VulnID+" rule "+$RuleID)}
        }
        if ($Details -ne $null)
        {
            if ($Details -eq "")
            {
                $Details = " " #Add whitespace to prevent blank string error
            }
            $Res = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "FINDING_DETAILS" -Value $Details
            if (-not $Res){Write-Warning ("Failed to write: details of vuln "+$VulnID+" rule "+$RuleID)}
        }
        if ($Comments -ne $null)
        {
            if ($Comments -eq "")
            {
                $Comments = " " #Add whitespace to prevent blank string error
            }
            $Res = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "COMMENTS" -Value $Comments
            if (-not $Res){Write-Warning ("Failed to write: comments of vuln "+$VulnID+" rule "+$RuleID)}
        }
    }
    else
    {
        #Write error if we were not passed a vuln or rule
        Write-Error "VulnID or RuleID must be set!"
    }
}

<#
.SYNOPSIS
    Gets the status of a single vuln check, or an array of the status of all vuln checks in a CKL

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to Get

.PARAMETER RuleID
    Rule_ID of the Vuln to Get

.PARAMETER NoAliases
    To help align function outputs and inputs, aliases are added. This will prevent aliases from being added to output
  
.EXAMPLE
    Get-VulnCheckResult -CKLData $CKLData -VulnID "V-11111"
#>
function Get-VulnCheckResult
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null, 
        $RuleID=$null,
        [switch]$NoAliases
    )
    #Pre set what we will return
    $Status, $Finding, $Comments = ""
    #If we have an ID of some sort
    if ($VulnID -ne $null -or $RuleID -ne $null)
    {
        #Use it to get the result values
        $Status = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "STATUS"
        $Finding = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "FINDING_DETAILS"
        $Comments = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "COMMENTS"
        if (-not $VulnID)
        {
            $VulnID = Get-VulnInfoAttribute -CKLData $CKLData -RuleID $RuleID -Attribute "Vuln_Num"
        }
        #Return it as a new object
        $ToReturn = New-Object -TypeName PSObject -Property @{Status=$Status;Finding=$Finding;Comments=$Comments; VulnID=$VulnID}
        if (-not $NoAliases) {
            Add-Member -InputObject $ToReturn -MemberType AliasProperty -Name "Details" -Value "Finding" -SecondValue System.String
            Add-Member -InputObject $ToReturn -MemberType AliasProperty -Name "Result" -Value "Status" -SecondValue System.String
        }
        return $ToReturn
    }
    else
    {
        #If we don't have an ID, return ALL of the stig results
        #TODO: We can seed this up, I'm sure
        $ToReturn = @()
        $VulnIDs = Get-VulnIDs -CKLData $CKLData
        foreach ($VulnID in $VulnIDs)
        {
            $Status = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -Attribute "STATUS"
            $Finding = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID  -Attribute "FINDING_DETAILS"
            $Comments = Get-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID  -Attribute "COMMENTS"
            $ToAdd = New-Object -TypeName PSObject -Property @{Status=""+$Status;Finding=""+$Finding;Comments=""+$Comments; VulnID=""+$VulnID}
            if (-not $NoAliases) {
                Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name "Details" -Value "Finding" -SecondValue System.String
                Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name "Result" -Value "Status" -SecondValue System.String
            }

            $ToReturn += $ToAdd
        }
        return $ToReturn
    }
}

<#
.SYNOPSIS
    Returns an array of the vulns in the CKL file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

.PARAMETER CKLData
    CKL data as loaded from the Import-StigCKL
  
.EXAMPLE
    Get-CKLVulnInformation -CKLData $CKLData
#>
function Get-CKLVulnInformation
{
    [Obsolete("Please use Get-VulnInformation instead.")] 
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData
    )
    $Results = @()
    $VulnIDs = Get-VulnIDs -CKLData $CKLData
    foreach ($VulnID in $VulnIDs) {
        $Description = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -Attribute Vuln_Discuss
        $Title = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -Attribute Rule_Title
        $Version = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -Attribute Rule_Ver
        $FixText = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -Attribute Fix_Text
        $CheckText = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -Attribute Check_Content
        $Results += New-Object -TypeName PSObject -Property @{ID=$VulnID;Title=$Title;Version=$Version;Description=$Description;FixText=$FixText;CheckText=$CheckText}
    }
    return $Results
}

<#
.SYNOPSIS
    Returns an array of the vulns in the CKL file and all it's associated informational properties (Vuln_ID, Rule_ID, CCI_REF etc)

.PARAMETER CKLData
    CKL data as loaded from the Import-StigCKL

.PARAMETER NoAliases
    Aliases are added for backwards compatibility with obsolete Get-CKLVulnInformation, this turns those off

.EXAMPLE
    Get-VulnInformation -CKLData $CKLData

.EXAMPLE
    Get-VulnInformation -CKLData $CKLData -NoAliases
#>
function Get-VulnInformation
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        [switch]$NoAliases
    )
    $Results = @()
    $VulnIDs = Get-VulnIDs -CKLData $CKLData
    foreach ($VulnID in $VulnIDs) {
        $VulnInfo = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA")
        $ToAdd = @{}
        foreach($Attribute in $VulnInfo) {
            if ($ToAdd.ContainsKey($Attribute.VULN_ATTRIBUTE)) {
                if ($ToAdd[$Attribute.VULN_ATTRIBUTE].GetType().BaseType -eq "System.Array") {
                    $ToAdd[$Attribute.VULN_ATTRIBUTE] += $Attribute.ATTRIBUTE_DATA
                } else {
                    $ToAdd[$Attribute.VULN_ATTRIBUTE] = @($ToAdd[$Attribute.VULN_ATTRIBUTE], $Attribute.ATTRIBUTE_DATA)
                }
            } else {
                $ToAdd+= @{$Attribute.VULN_ATTRIBUTE=$Attribute.ATTRIBUTE_DATA}
            }
        }
        $ToAdd = New-Object -TypeName PSObject -Property $ToAdd

        #Add some aliases
        if (-not $NoAliases) {
            Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name Description -Value "Vuln_Discuss" -SecondValue System.String
            Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name Title -Value "Rule_Title" -SecondValue System.String
            Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name Version -Value "Rule_Ver" -SecondValue System.String
            Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name FixText -Value "Fix_Text" -SecondValue System.String
            Add-Member -InputObject $ToAdd -MemberType AliasProperty -Name CheckText -Value "Check_Content" -SecondValue System.String
        }

        $Results += $ToAdd
    }
    return $Results
}

<#
.SYNOPSIS
    Load a CKL file as an [XML] element. This can then be passed to other functions in this module.

.PARAMETER Path
    Full path to the CKL file
  
.EXAMPLE
    Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#>
function Import-StigCKL
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    return [XML](Get-Content -Path $Path -Encoding UTF8)
}

<#
.SYNOPSIS
    Saves a loaded CKL file to disk

.PARAMETER CKLData
    The loaded CKL Data as loaded by Import-StigCKL

.PARAMETER Path
    Full path to the CKL file

.PARAMETER AddHostData
    Automatically adds the running hosts information into the CKL before saving

.EXAMPLE
    Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl"

.EXAMPLE
    Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl" -AddHostData
#>
function Export-StigCKL
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, 
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$AddHostData
    )
    #Set XML Options to replicate those of the STIG Viewer application
    $XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
    $XMLSettings.Indent = $true;
    $XMLSettings.IndentChars = "`t"
    $XMLSettings.NewLineChars="`n"
    $XMLSettings.Encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    $XMLSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Document

    #Add Host data if requested
    if ($AddHostData)
    {
        Set-CKLHostData -CKLData $CKLData -AutoFill
    }
    $XMLWriter = [System.XML.XmlWriter]::Create($Path, $XMLSettings)
    #Save the data
    $CKLData.Save($XMLWriter)
    $XMLWriter.Flush()
    $XMLWriter.Dispose();
}

<#
.SYNOPSIS
    Opens and re-saves a CKL, may fix formatting issues

.PARAMETER Path
    Full path to the CKL file
  
.EXAMPLE
    Repair-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#>
function Repair-StigCKL
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    #Load
    $CKLData = Import-StigCKL -Path $Path
    #Save
    Export-StigCKL -CKLData $CKLData -Path $Path
}

<#
.SYNOPSIS
    Gets the host information from the CKLData

.PARAMETER CKLData
    CKL Data as loaded by Import-StigCKL
  
.EXAMPLE
    Get-CKLHostData -CKLData $CKLData
#>
function Get-CKLHostData
{
    Param([Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData)
    #Return PSObject of the host info
    return New-Object -TypeName PSObject -Property @{HostName=$CKLData.CHECKLIST.ASSET.HOST_NAME; HostIP=$CKLData.CHECKLIST.ASSET.HOST_IP;
        HostMAC=$CKLData.CHECKLIST.ASSET.HOST_MAC;HostGUID=$CKLData.CHECKLIST.ASSET.HOST_GUID;HostFQDN=$CKLData.CHECKLIST.ASSET.HOST_FQDN;
        Role=$CKLData.CHECKLIST.ASSET.ROLE}
}

<#
.SYNOPSIS
    Sets a vuln status based on a registry check

.PARAMETER CKLData
    CKL Data as loaded by Import-StigCKL

.PARAMETER VulnID
    ID Of the STIG check to set

.PARAMETER RegKeyPath
    Path to the registry key

.PARAMETER RequiredKey
    Key name

.PARAMETER RequiredValue
    Value the key should be to pass check

.PARAMETER Comments
    Value to set Comments to
  
.EXAMPLE
    Set-VulnCheckResultFromRegistry -CKLData $CKLData -RegKeyPath "HKLM:\SOFTWARE\COMPANY\DATA" -RequiredKey "PortStatus" -RequiredValue "Closed" -Comments "Checked by asdf"
#>
function Set-VulnCheckResultFromRegistry
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$VulnID,
        [Parameter(Mandatory=$true)][string]$RegKeyPath,
        [Parameter(Mandatory=$true)][string]$RequiredKey,
        [Parameter(Mandatory=$true)]$RequiredValue,
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        [string]$Comments
    )
    if ($Comments -eq $null -or $Comments -eq "") {
        $Comments = " ";
    }
    #Check if key exists
    if (Test-Path -Path $RegKeyPath)
    {
        #If it does get the property
        $RegistryKeyProps = Get-ItemProperty -Path $RegKeyPath
        #Check if the property matches required value
        if ($RegistryKeyProps.$RequiredKey -eq $RequiredValue)
        {
            #If it does, saves as notafinding
            $Details = "Required key $RequiredKey is "+$RequiredValue.ToString()
            Set-VulnCheckResult -CKLData $CKLData -VulnID $VulnID -Details $Details -Comments $Comments -Result NotAFinding
        }
        else
        {
            #If it does not, set it to open
            $Details = "Required key $RequiredKey is "
            if ($RegistryKeyProps.$RequiredKey -eq $null)
            {
                $Details+="null"
            }
            else
            {
                $Details+=$RegistryKeyProps.$RequiredKey.ToString()
            }
            Set-VulnCheckResult -CKLData $CKLData -VulnID $VulnID -Details $Details -Comments $Comments -Result Open
        }
    }
    else
    {
        #If not, set the check to failed
        $Details = "Required key path $RegKeyPath does not exist"
        Set-VulnCheckResult -CKLData $CKLData -VulnID $VulnID -Details $Details -Comments $Comments -Result Open
    }
}


<#
.SYNOPSIS
    Sets host data in CKL. If any parameters are blank, they will be set to running machine

.PARAMETER CKLData
    CKL Data as loaded by Import-StigCKL

.PARAMETER Host
    Short host name

.PARAMETER FQDN
    Fully qualified domain name

.PARAMETER Mac
    Mac of the host

.PARAMETER IP
    IP address of the host

.PARAMETER TargetComments
    TargetComments of the host

.PARAMETER TargetCommentsFromAD
    Fills target comments from the machines AD description, if exists and found.

.PARAMETER IsWebOrDB
    Manually selects the Web or DB STIG setting. This is auto-set to true if webdbsite or webdbinstance is provided while this is $null

.PARAMETER WebDBSite
    Sets the web or db site STIG for the CKL. Will autoset IsWebOrDB to true if this is provided and IsWebOrDB is not.

.PARAMTER WebDBInstance
    Sets the web or db instance STIG for the CKL. Will autoset IsWebOrDB to true if this is provided and IsWebOrDB is not.
  
.EXAMPLE
    Set-CKLHostData -CKLData $CKLData -AutoFill

.EXAMPLE
    Set-CKLHostData -CKLData $CKLData -Host "SomeMachine" -FQDN "SomeMachine.Some.Domain.com" -Mac "00-00-00-..." -IP "127.0.0.1"
#>
function Set-CKLHostData
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $Host,
        $FQDN,
        $Mac,
        $IP,
        $TargetComments,
        $WebDBSite,
        $WebDBInstance,
        [ValidateSet("true",
            "false",
            $true,
            $false,$null)]$IsWebOrDB,
        [ValidateSet("None",
            "Workstation",
            "Member Server",
            "Domain Controller",$null)]$Role,
        [switch]$AutoFill,
        [switch]$TargetCommentsFromAD
    )
    if ($AutoFill) {
        if ($Host -eq $null) {
            $Host = (Get-WmiObject -Class Win32_ComputerSystem).Name
        }
        if ($FQDN -eq $null) {
            $FQDN = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Host).Name+(Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Host).Domain
        }
        if ($Mac -eq $null) {
            $Mac = (@()+(Get-WMIObject win32_networkadapterconfiguration -ComputerName $Host | Where-Object -FilterScript {$_.IPAddress -ne $null}))[0].Macaddress
        }
        if ($IP -eq $null) {
            $IP = (@()+(Get-WMIObject win32_networkadapterconfiguration -ComputerName $Host | Where-Object -FilterScript {$_.IPAddress -ne $null}))[0].IPAddress[0]
        }
        if ($Role -eq $null) {
            $Role = "None"
            $PType = (Get-WmiObject -Class Win32_OperatingSystem -Property ProductType -ComputerName $Host).ProductType
            if ($PType -eq 1) {
                $Role = "Workstation"
            }
            if ($PType -eq 3) {
                $Role = "Member Server"
            }
            if ($PType -eq 2) {
                $Role = "Domain Controller"
            }
        }
    }
    if ($TargetCommentsFromAD -and $TargetComments -eq $null) {
        $ComputerData = Get-ADComputer -Identity $Computer -Properties Description -ErrorAction SilentlyContinue
        if ($ComputerData -ne $null) {
            $TargetComments = $ComputerData.Description
        }
    }
    #Set the various properties
    if ($Host -ne $null) {
        $CKLData.CHECKLIST.ASSET.HOST_NAME = $Host.ToString()
    }
    if ($FQDN -ne $null) {
        $CKLData.CHECKLIST.ASSET.HOST_FQDN = $FQDN.ToString()
    }
    if ($IP -ne $null) {
        $CKLData.CHECKLIST.ASSET.HOST_IP = $IP.ToString()
    }
    if ($Mac -ne $null) {
        $CKLData.CHECKLIST.ASSET.HOST_MAC = $Mac.ToString()
    }
    if ($Role -ne $null) {
        $CKLData.CHECKLIST.ASSET.ROLE = $Role.ToString()
    }
    if ($TargetComments -ne $null) {
        $CKLData.CHECKLIST.ASSET.TARGET_COMMENT = $TargetComments.ToString()
    }
    if ($IsWebOrDB -eq $null -and ($WebDBSite -ne $null -or $WebDBInstance -ne $null)) {
        $CKLData.CHECKLIST.ASSET.WEB_OR_DATABASE = "true"
    } elseif ($IsWebOrDB -ne $null) {
        $CKLData.CHECKLIST.ASSET.WEB_OR_DATABASE = $IsWebOrDB.ToString().ToLower()
    }
    if ($WebDBSite -ne $null) {
        $CKLData.CHECKLIST.ASSET.WEB_DB_SITE = $WebDBSite.ToString()
    }
    if ($WebDBInstance -ne $null) {
        $CKLData.CHECKLIST.ASSET.WEB_DB_INSTANCE = $WebDBInstance.ToString()
    }
}

<#
.SYNOPSIS
    Merges two loaded CKLs

.PARAMETER SourceCKL
    The CKL that contains the data to merge, as from Import-StigCKL

.PARAMETER DestinationCKL
    The CKL that the data should merge into, as from Import-StigCKL

.PARAMETER IncludeNR
    If this is set, Items marks at "Not_Reviewed" will overwrite the destination, otherwise only answered items are merged
  
.EXAMPLE
    Merge-CKLData -SourceCKL $OriginalInfo -DestinationCKL $NewCKL
#>
function Merge-CKLData
{
    Param
    (
        [Parameter(Mandatory=$true)][XML]$SourceCKL,
        [Parameter(Mandatory=$true)][XML]$DestinationCKL,
        [switch]$IncludeNR,
        [switch]$DontCopyHostInfo,
        [switch]$DontOverwriteVulns
    )
    #Get the stig results form the source
    Write-Progress -Activity "Merging" -CurrentOperation "Loading old results"
    $StigResults = Get-VulnCheckResult -CKLData $SourceCKL
    $DestinationIDs = (Get-VulnCheckResult -CKLData $DestinationCKL).VulnID
    $I=0;
    Write-Progress -Activity "Merging" -CurrentOperation "Writing results" -PercentComplete (($I*100)/$StigResults.Length)
    #Import them into the destination
    foreach ($Result in $StigResults)
    {
        if ($DestinationIDs.Contains($Result.VulnID)) {
            if ($Result.Status -ne "Not_Reviewed" -or $IncludeNR) {
                if ($DontOverwriteVulns) {
                    $PrevResult = Get-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID
                    if ($PrevResult -eq $null -or $PrevResult.Status -eq "Not_Reviewed") {
                        Set-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID -Details $Result.Finding -Comments $Result.Comments -Result $Result.Status
                    }
                }
                else
                {
                    Set-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID -Details $Result.Finding -Comments $Result.Comments -Result $Result.Status
                }
            }
        } else {
            Write-Warning "$($Result.VulnID) does not exist in the destination. Maybe removed in a newer version?"
        }
        $I++;
        Write-Progress -Activity "Merging" -PercentComplete (($I*100)/$StigResults.Length)
    }
    #Copy over host info
    if (-not $DontCopyHostInfo) {
        $HostInfo = Get-CKLHostData -CKLData $SourceCKL
        Set-CKLHostData -CKLData $DestinationCKL -Host $HostInfo.HostName -FQDN $HostInfo.HostFQDN -Mac $HostInfo.HostMAC -IP $HostInfo.HostIP -Role $HostInfo.Role
    }
    Write-Progress -Activity "Merging" -PercentComplete 100 -Completed
}

<#
.SYNOPSIS
    Merges two CKL files and saves it as a new CKL. Largely a wrapper around Merge-CKLData.

.PARAMETER SourceCKLFile
    The CKL file path that contains the data to merge

.PARAMETER DestinationCKLFile
    The CKL file path that the data should merge into

.PARAMETER IncludeNR
    If this is set, Items marks at "Not_Reviewed" will overwrite the destination, otherwise only answered items are merged
  
.PARAMETER DontCopyHostInfo
    Does not overwrite desination's host data

.PARAMETER DontOverwriteVulns
    Does not overwrite desination's vuln findings. Result is only Not_Reviewed checks are filled.
  
.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl"

.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\ManualChecks.ckl" -DestinationCKLFile "C:\CKLS\ScapResults.ckl" -SaveFilePath "C:\CKLS\MergedChecks.ckl" -DontCopyHostInfo -DontOverwriteVulns

.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl" -IncludeNR
#>
function Merge-CKLs
{
    Param
    (
        [Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$DestinationCKLFile,
        [Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$SourceCKLFile,
        [Parameter(Mandatory=$true)][string]$SaveFilePath,
        [switch]$IncludeNR,
        [switch]$DontCopyHostInfo,
        [switch]$DontOverwriteVulns
    )
    #Load both inputs
    $DestinationCKL = Import-StigCKL -Path $DestinationCKLFile
    $SourceCKL = Import-StigCKL -Path $SourceCKLFile
    #Merge 'em
    Merge-CKLData -SourceCKL $SourceCKL -DestinationCKL $DestinationCKL -IncludeNR:$IncludeNR -DontCopyHostInfo:$DontCopyHostInfo -DontOverwriteVulns:$DontOverwriteVulns
    #Save output
    Export-StigCKL -CKLData $DestinationCKL -Path $SaveFilePath
}

<#
.SYNOPSIS
    Returns a complex object of metrics on the statuses of the checks in a directory of checklists, or a checklist

.PARAMETER CKLDirectory
    Path to folder container the ckls to pull metrics on
  
.EXAMPLE
    Get-StigMetrics -CKLDirectory "C:\CKLS\"
#>
function Get-StigMetrics
{
    Param([Alias("CKLDirectory")]$Path)

    if ((Get-Item $Path) -is [system.io.fileinfo] -and $Path -like "*.ckl") {
        $CKFiles = @()+(Get-Item $Path)
    } else {
        #AllChecklists
        $CKFiles = Get-ChildItem -Path $Path -Filter "*.ckl" -Recurse
    }
    $IndividualStigs = @{}
    $Open = 0
    $NAF = 0
    $NA = 0
    $NR = 0
    $Categories = @{
                        Cat1=New-Object -TypeName PSObject -Property @{UniqueTotal=0;Total=0;Open=0;NotReviewed=0;NotApplicable=0;NotAFinding=0};
                        Cat2=New-Object -TypeName PSObject -Property @{UniqueTotal=0;Total=0;Open=0;NotReviewed=0;NotApplicable=0;NotAFinding=0};
                        Cat3=New-Object -TypeName PSObject -Property @{UniqueTotal=0;Total=0;Open=0;NotReviewed=0;NotApplicable=0;NotAFinding=0}
                   }
    Write-Progress -Activity "Aggregating Data" -Status "Starting" -PercentComplete 0
    $Processed=0;
    foreach ($CKL in $CKFiles)
    {
        Write-Progress -Activity "Aggregating Data" -Status $CKL.Name -PercentComplete (($Processed/$CKFiles.Length)*100)
        $CKLData = Import-StigCKL -Path $CKL.FullName
        $Results = Get-VulnCheckResult -CKLData $CKLData
        #Add to grand totals
        $Open+= (@()+($Results | Where-Object {$_.Status -eq "Open"})).Count
        $NAF+= (@()+($Results | Where-Object {$_.Status -eq "NotAFinding"})).Count
        $NA+= (@()+($Results | Where-Object {$_.Status -eq "Not_Applicable"})).Count
        $NR+= (@()+($Results | Where-Object {$_.Status -eq "Not_Reviewed"})).Count
        #Add to sub totals
        foreach ($Stig in $Results)
        {
            #Convert Cat to match table
            $Cat = Get-VulnInfoAttribute -CKLData $CKLData -VulnID $Stig.VulnID -Attribute Severity
            if ($Cat -eq "low") {
                $Cat = "Cat3"
            } elseif ($Cat -eq "medium") {
                $Cat = "Cat2"
            } elseif ($Cat -eq "high" -or $Cat -eq "critical") {
                $Cat = "Cat1"
            }
            #Increment total for cat
            $Categories[$Cat].Total += 1;

            #Add stig if not already being tracked
            if (-not $IndividualStigs.ContainsKey($Stig.VulnID)) {
                $IndividualStigs += @{$Stig.VulnID=(New-Object -TypeName PSObject -Property @{VulnID=$Stig.VulnID; Open=0; NotApplicable = 0; NotAFinding=0; NotReviewed=0; Category=$Cat})}
                $Categories[$Cat].UniqueTotal += 1;
            }
            #Track it
            if ($Stig.Status -eq "Open") {
                $IndividualStigs[$Stig.VulnID].Open++;
                $Categories[$Cat].Open += 1;
            } elseif ($Stig.Status -eq "Not_Applicable") {
                $IndividualStigs[$Stig.VulnID].NotApplicable++;
                $Categories[$Cat].NotApplicable += 1;
            } elseif ($Stig.Status -eq "NotAFinding") {
                $IndividualStigs[$Stig.VulnID].NotAFinding++;
                $Categories[$Cat].NotAFinding += 1;
            } elseif ($Stig.Status -eq "Not_Reviewed") {
                $IndividualStigs[$Stig.VulnID].NotReviewed++;
                $Categories[$Cat].NotReviewed += 1;
            }
        }
        $Processed++;
    }
    Write-Progress -Activity "Finalizing Data" -PercentComplete 100
    #Looks odd but cleans up the output
    $IndividualScores = @()
    foreach ($Value in $IndividualStigs.Values)
    {
        $IndividualScores += New-Object -TypeName PSObject -Property @{VulnID=$Value.VulnID; Open=$Value.Open; NotApplicable = $Value.NotApplicable; NotAFinding=$Value.NotAFinding; NotReviewed=$Value.NotReviewed }
    }
    $FindingScores = New-Object -TypeName PSObject -Property @{Open=$Open; NotApplicable = $NA; NotAFinding=$NAF; NotReviewed=$NR; Total=$Open+$NAF+$NA+$NR;}
    Write-Progress -Activity "Finalizing Data" -PercentComplete 100 -Completed
    #return the output
    return (New-Object -TypeName PSObject -ArgumentList @{TotalFindingScores = $FindingScores; IndividualVulnScores = $IndividualScores; CategoryScores = $Categories})
}
#endregion

#region XCCDF Functions
<#
.SYNOPSIS
    Load an XCCDF file into a [xml]

.PARAMETER Path
    Path to the XCCDF file
  
.EXAMPLE
    Import-XCCDF -Path C:\XCCDF\Results.xml
#>
function Import-XCCDF
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    return [XML](Get-Content -Encoding UTF8 -Path $Path)
}

<#
.SYNOPSIS
    Returns stig results from an XCCDF file

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF
  
.EXAMPLE
    Get-XCCDFResults -XCCDF (Import-XCCDF -Path C:\XCCDF\Results.xml)
#>
function Get-XCCDFResults
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF)
    #Grab rule results
    $Results = $XCCDF.Benchmark.TestResult.'rule-result'
    $ToReturn = @()
    #Loop through them
    foreach ($Result in $Results)
    {
        #Get IP
        if ($Result.idref -match "(SV-.*_rule)")
        {
            $Result.idref = $Matches[1]
        }
        #Return ID and result
        $ToReturn += New-Object PSObject -Property @{RuleID=$Result.idref;Result=$Result.result}
    }
    return $ToReturn
}

<#
.SYNOPSIS
    Adds XCCDF results into a loaded CKL data

.PARAMETER CKLData
    CKL Data as loaded by Import-StigCKL

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF

.PARAMETER NoCommentsOnOpen
    Will not write custom comments over previous comments if the check is open
  
.EXAMPLE
    Merge-XCCDFToCKL -CKLData $CKLData -XCCDF $XCCDFData
#>
function Merge-XCCDFToCKL
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, 
        [Parameter(Mandatory=$true)][xml]$XCCDF,
        [switch]$NoCommentsOnOpen
    )
    #Grab the results from the XCCDF Data
    $Results = Get-XCCDFResults -XCCDF $XCCDF
    $PrevResults = $null
    if ($NoCommentsOnOpen) {
        $PrevResults = Get-VulnCheckResult -CKLData $CKLData
    }
    $I=0;
    Write-Progress -Activity "Importing" -PercentComplete (($I*100)/$Results.Count)
    #Loop through them
    foreach ($Result in $Results)
    {
        #Convert result to CKL result
        $Res = "Open"
        if ($Result.result -eq "pass")
        {
            $Res = "NotAFinding"   
        }

        $Details = "Checked by SCAP tool"
        $Comments = "Checked by SCAP tool"
        
        if ($NoCommentsOnOpen) {
            $PrevResult = $PrevResults | Where-Object {$_.RuleID -eq $Result.RuleID}
            if ($PrevResult -ne $null -and $PrevResult.Status -ne "NotAFinding") {
                $Details = $PrevResult.Finding
                $Comments = $PrevResult.Comments
            }
        }

        #Set it in the CKL
        Set-VulnCheckResult -CKLData $CKLData -RuleID $Result.RuleID -Result $Res -Details $Details -Comments $Comments
        $I++;
        Write-Progress -Activity "Importing" -PercentComplete (($I*100)/$Results.Count)
    }
    #Add machine into from XCCDF
    Merge-XCCDFHostDataToCKL -CKLData $CKLData -XCCDF $XCCDF
    Write-Progress -Activity "Importing" -PercentComplete 100 -Completed
}

<#
.SYNOPSIS
    Adds XCCDF host info into a loaded CKL data

.PARAMETER CKLData
    CKL Data as loaded by Import-StigCKL

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF
  
.EXAMPLE
    Merge-XCCDFHostDataToCKL -CKLData $CKLData -XCCDF $XCCDFData
#>
function Merge-XCCDFHostDataToCKL
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, 
        [Parameter(Mandatory=$true)][xml]$XCCDF
    )
    #Get machine info
    $MachineInfo = Get-XCCDFHostData -XCCDF $XCCDF
    #Add it to CKL
    Set-CKLHostData -CKLData $CKLData -Host $MachineInfo.HostName -IP $MachineInfo.HostIP -Mac $MachineInfo.HostMAC -FQDN $MachineInfo.HostFQDN
}

<#
.SYNOPSIS
    Gets host info from XCCDF

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF

.PARAMETER Filter
    If provided, this will be used to select a specific IP/MAC pair from the XCCDF file. Consider filtering on interface_name, ipv4 or mac and check for nulls

.EXAMPLE
    Get-XCCDFHostData -XCCDF $XCCDFData

.EXAMPLE
    Get-XCCDFHostData -XCCDF $XCCDFData -Filter {$_.ipv4 -ne $null -and $_.ipv4 -like "192.133.*"}
#>
function Get-XCCDFHostData
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF, [scriptblock]$Filter)

    #Init variables with empty string
    $HostName, $HostIP, $HostMAC, $HostGUID, $HostFQDN = ""
    #Load info
    $Facts = Get-XCCDFTargetFacts -XCCDF $XCCDF
    $HostName = $XCCDF.Benchmark.TestResult.target
    $HostFQDN = $Facts.FQDN
    $HostGUID = $Facts.GUID

    if ($Filter -eq $null) {
        #If no filter provided, we use first target-address for the host info
        $HostIP = (@()+($XCCDF.Benchmark.TestResult.'target-address' | Where-Object -FilterScript {$_ -ne $null -and $_ -ne ""}))[0] #Grab first IP, that is not blank, from targets
        $HostMAC = $Facts.Interfaces | Where-Object -FilterScript {$_.IPv4 -eq $HostIP} #Try and get matching MAC for the specified IP
        if ($HostMAC -ne $null -and $HostMAC.MAC -ne $null -and $HostMAC.MAC -ne "") {
            $HostMAC = $HostMAC.MAC #If we succeed, ensure we return the MAC itself
        } elseif($Facts.Interfaces.Length -gt 0) {
            #If we fail, default to old style of grabing first available MAC, even if it does not match ip, from the XCCDF file
            $HostMAC = $Facts.Interfaces[0].Mac
        }
    } else {
        #If we have a filter, use that to select the IP and MAC reported
        $SelectedInterface=(@()+($Facts.Interfaces | Where-Object -FilterScript:$Filter))
        if ($SelectedInterface.Length -eq 0) {
            Write-Warning -Message "Filter did not match any interfaces. IP and MAC will be blank"
        } else {
            if ($SelectedInterface.Length -gt 1) {
                Write-Warning -Message "Filter matched multiple interfaces, first interface matched will be used"
            }
            $HostIP = $SelectedInterface[0].ipv4
            $HostMAC = $SelectedInterface[0].mac
        }
    }
    #Note, XCCDF Does not have a role field, so it will not be filled
    #Return host info
    return (New-Object -TypeName PSObject -Property @{HostName=$HostName;HostIP=$HostIP;HostMac=$HostMAC;HostFQDN=$HostFQDN;HostGUID=$HostGUID})
}

<#
.SYNOPSIS
    Gets all target facts from an XCCDF

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF
  
.EXAMPLE
    Get-XCCDFTargetFacts -XCCDF $XCCDFData
#>
function Get-XCCDFTargetFacts
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF)
    #Pre fill variables
    $ToReturn = New-Object -TypeName PSObject -Property @{Interfaces=@()}

    #Grab all facts
    $Facts = $XCCDF.Benchmark.TestResult.'target-facts'.fact
    #Storage for interface data
    $Interface = $null
    #Loop through all facts
    for ($I=0; $I -lt $Facts.Length; $I++) {
        #If we hit an interface name
        if ($Facts[$I].Name -eq "urn:scap:fact:asset:identifier:interface_name") {
            if ($Interface -ne $null) {
                #Add the current interface to the return object
                $ToReturn.Interfaces+=$Interface
            }
            #Create a new empty interface
            $Interface = New-Object -TypeName PSObject
        }
        #Add the new fact to the interface, if we are processsing interfaces, or directly to the return object otherwise
        if ($Interface -ne $null) {
            $Interface | Add-Member -Name $Facts[$I].Name.Replace("urn:scap:fact:asset:identifier:","") -MemberType NoteProperty -Value $Facts[$I]."#text"
        } else {
            $ToReturn | Add-Member -Name $Facts[$I].Name.Replace("urn:scap:fact:asset:identifier:","") -MemberType NoteProperty -Value $Facts[$I]."#text"
        }
    }
    #Last interface still needs to be added if it exists
    if ($Interface -ne $null) {
        $ToReturn.Interfaces+=$Interface
    }

    #Return processed facts
    return $ToReturn
}

<#
.SYNOPSIS
    Gets general info from the XCCDF (Release, Title, Description)

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF
  
.EXAMPLE
    Get-XCCDFInfo -XCCDF $XCCDFData
#>
function Get-XCCDFInfo
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF)
    $Version = ($XCCDF.Benchmark.'plain-text' | Where-Object {$_.id -eq 'release-info'}).'#text'
    return (New-Object -TypeName PSObject -Property @{Title=$XCCDF.Benchmark.title;Description=$XCCDF.Benchmark.description;Release=$Version; Version=$XCCDF.Benchmark.version; ID = $XCCDF.Benchmark.id})
}

<#
.SYNOPSIS
    Returns an array of the vulns in the xccdf file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF

.PARAMETER Full
    If supplied, will pull all information in a less friendly format.
  
.EXAMPLE
    Get-XCCDFVulnInformation -XCCDF $XCCDFData

.EXAMPLE
    Get-XCCDFVulnInformation -XCCDF $XCCDFData -Full
#>
function Get-XCCDFVulnInformation {
    Param([Parameter(Mandatory=$true)][xml]$XCCDF, [Switch]$Full)
    $Results = @()
    $Groups = $XCCDF.Benchmark.Group
    foreach ($Group in $Groups) {
        if (-not $Full) {
            $Description = $Group.Rule.description;
            #Description is weird, it is like further XML, but encoded and not as separate elements. idk, but this regex will extract what we want out of the mess
            if ($Description -match "<VulnDiscussion\>([\w\W]*)</VulnDiscussion>") {
                $Description = $Matches[1]
            }
            $Results += New-Object -TypeName PSObject -Property @{ID=$Group.id;Title=$Group.Rule.Title;Version=$Group.Rule.Version;Description=$Description;FixText=$Group.Rule.fixtext.'#text';CheckText=$Group.Rule.check.'check-content'}
        } else {
            #Breakout Description
            $Description = $Group.Rule.description
            if ($Description -match "<VulnDiscussion\>([\w\W]*)</VulnDiscussion>") {
                $Description = $Matches[1]
            }
            $FalsePositives = ""
            if ($Group.Rule.description -match "<FalsePositives\>([\w\W]*)</FalsePositives>") {
                $FalsePositives = $Matches[1]
            }
            $FalseNegatives = ""
            if ($Group.Rule.description -match "<FalseNegatives\>([\w\W]*)</FalseNegatives>") {
                $FalseNegatives = $Matches[1]
            }
            $Documentable = ""
            if ($Group.Rule.description -match "<Documentable\>([\w\W]*)</Documentable>") {
                $Documentable = $Matches[1]
            }
            $Mitigations = ""
            if ($Group.Rule.description -match "<Mitigations\>([\w\W]*)</Mitigations>") {
                $Mitigations = $Matches[1]
            }
            $SeverityOverrideGuidance = ""
            if ($Group.Rule.description -match "<SeverityOverrideGuidance\>([\w\W]*)</SeverityOverrideGuidance>") {
                $SeverityOverrideGuidance = $Matches[1]
            }
            $PotentialImpacts = ""
            if ($Group.Rule.description -match "<PotentialImpacts\>([\w\W]*)</PotentialImpacts>") {
                $PotentialImpacts = $Matches[1]
            }
            $ThirdPartyTools = ""
            if ($Group.Rule.description -match "<ThirdPartyTools\>([\w\W]*)</ThirdPartyTools>") {
                $ThirdPartyTools = $Matches[1]
            }
            $MitigationControl = ""
            if ($Group.Rule.description -match "<MitigationControl\>([\w\W]*)</MitigationControl>") {
                $MitigationControl = $Matches[1]
            }
            $Responsibility = ""
            if ($Group.Rule.description -match "<Responsibility\>([\w\W]*)</Responsibility>") {
                $Responsibility = $Matches[1]
            }
            $IAControls = ""
            if ($Group.Rule.description -match "<IAControls\>([\w\W]*)</IAControls>") {
                $IAControls = $Matches[1]
            }


            $Check = New-Object PSObject -Property @{ System=$Group.Rule.check.system; ContentRefName = $Group.Rule.check.'check-content-ref'.name;
                ContentRefHREF=$Group.Rule.check.'check-content-ref'.href; Content = $Group.Rule.check.'check-content'; }

            $Reference = New-Object PSObject -Property @{ Title = $Group.Rule.reference.title; Publisher = $Group.Rule.reference.publisher;
                Type=$Group.Rule.reference.type; Subject = $Group.Rule.reference.subject; Identifier = $Group.Rule.reference.identifier;}

            $Rule = New-Object PSObject -Property @{ID=$Group.Rule.id; Version = $Group.Rule.version; Severity = $Group.Rule.severity; 
                Weight = $Group.Rule.weight; Title=$Group.Rule.title; Description=$Description; Ident = $Group.Rule.ident.InnerText;
                IdentSystem = $Group.Rule.ident.system; FixText = $Group.Rule.fixtext.InnerText; FixTextRef = $Group.Rule.fixtext.fixref;
                FixID = $Group.Rule.fix.id; Check=$Check; Reference = $Reference; FalsePositives = $FalsePositives; FalseNegatives=$FalseNegatives;
                Documentable=$Documentable; Mitigations=$Mitigations; SeverityOverrideGuidance=$SeverityOverrideGuidance; PotentialImpacts=$PotentialImpacts;
                ThirdPartyTools=$ThirdPartyTools; MitigationControl=$MitigationControl; Responsibility=$Responsibility; IAControls=$IAControls}

            $Results += New-Object PSObject -Property @{ID=$Group.id; Title=$Group.title; Description = $Group.description; Rule=$Rule}
        }
    }
    return $Results
}

<#
Internal Helper Function to create plain XML nodes (Literally form of <name>text</name>)
#>
function Add-XMLTextNode {
    Param([Parameter(Mandatory=$true)][System.Xml.XmlDocument]$RootDocument, [Parameter(Mandatory=$true)][System.XML.XMLElement]$ParentNode, [Parameter(Mandatory=$true)][string]$Name, [string]$Text)
    $NewNode = $RootDocument.CreateElement($Name);
    $a = $NewNode.AppendChild($RootDocument.CreateTextNode($Text));
    $a = $ParentNode.AppendChild($NewNode);
}

<#
Internal Helper Function to create SI_DATA XML nodes
#>
function Add-SIDataNode {
    Param([Parameter(Mandatory=$true)][System.Xml.XmlDocument]$RootDocument, [Parameter(Mandatory=$true)][System.XML.XMLElement]$ParentNode, [Parameter(Mandatory=$true)][string]$Name, $Data)
    $NewNode = $RootDocument.CreateElement("SI_DATA");
    Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "SID_NAME" -Text $Name
    if ($Data -ne $null) {
        Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "SID_DATA" -Text $Data
    }
    $a = $ParentNode.AppendChild($NewNode);
}

<#
Internal Helper Function to create STIG_DATA XML nodes
#>
function Add-STIGDataNode {
    Param([Parameter(Mandatory=$true)][System.Xml.XmlDocument]$RootDocument, [Parameter(Mandatory=$true)][System.XML.XMLElement]$ParentNode, [Parameter(Mandatory=$true)][string]$Name, [string]$Data)
    $NewNode = $RootDocument.CreateElement("STIG_DATA");
    Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "VULN_ATTRIBUTE" -Text $Name
    Add-XMLTextNode -RootDocument $RootDocument -ParentNode $NewNode -Name "ATTRIBUTE_DATA" -Text $Data
    $a = $ParentNode.AppendChild($NewNode);
}

<#
.SYNOPSIS
    Will convert a manual xccdf to a blank checklist

.PARAMETER XCCDFPath
    Full file path to the XCCDF File (Required as one property of the file include the file name)

.PARAMETER SaveLocation
    Full path to save the new CKL file to

.EXAMPLE
    Convert-ManualXCCDFToCKL -XCCDFPath "C:\Data\U_MyApp_Manual.xccdf" -SaveLocation "C:\Data\MyChecklist.ckl"
#>
function Convert-ManualXCCDFToCKL {
    Param([Parameter(Mandatory=$true)][string]$XCCDFPath, $SaveLocation)
    $XCCDF = Import-XCCDF -Path $XCCDFPath
    $XCCDFData = Get-XCCDFVulnInformation -XCCDF $XCCDF -Full
    $XCCDFHeadData = Get-XCCDFInfo -XCCDF $XCCDF

    #Create XML
    $ToSave = New-Object System.Xml.XmlDocument
    #Header
    $a = $ToSave.AppendChild($ToSave.CreateXmlDeclaration("1.0", "UTF=8", $null));
    $a = $ToSave.AppendChild($ToSave.CreateComment("STIG Support Module"));
    #Root
    $a = $ToSave.AppendChild($ToSave.CreateElement("CHECKLIST"));

    #Asset Data
    $AssetNode = $ToSave.CreateElement("ASSET")
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "ROLE" -Text "None"
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "ASSET_TYPE" -Text "Computing"
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "HOST_NAME" -Text ""
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "HOST_IP" -Text ""
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "HOST_MAC" -Text ""
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "HOST_FQDN" -Text ""
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "TECH_AREA" -Text ""
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "TARGET_KEY" -Text ($XCCDFData[0].Rule.Reference.Identifier)
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "WEB_OR_DATABASE" -Text "false"
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "WEB_DB_SITE" -Text ""
    Add-XMLTextNode -RootDocument $ToSave -ParentNode $AssetNode -Name "WEB_DB_INSTANCE" -Text ""
    $a = $ToSave.LastChild.AppendChild($AssetNode);

    #STIGS
    $StigNode = $ToSave.CreateElement("STIGS");
    $iSTIGNode = $ToSave.CreateElement("iSTIG");
    $StigInfoNode = $ToSave.CreateElement("STIG_INFO")

    ##SI_DATA Stuff
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "version" -Data $XCCDFHeadData.Version
    #TODO: Verify if this is best way to check classification, from XCCDF, if not fix. Also, what are the other values?
    $Classification = ""
    $Class = ""
    if ($XCCDF.'xml-stylesheet'.Contains("unclass")) {
        $Classification = "UNCLASSIFIED"
        $Class="Unclass"
    }
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "classification" -Data $Classification
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "customname" -Data $null
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "stigid" -Data $XCCDFHeadData.ID
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "description" -Data $XCCDFHeadData.Description
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "filename" -Data (Get-Item -Path $XCCDFPath).Name
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "releaseinfo" -Data $XCCDFHeadData.Release
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "title" -Data $XCCDFHeadData.Title
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "uuid" -Data (New-Guid).ToString()
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "notice" -Data $XCCDF.Benchmark.notice.id
    Add-SIDataNode -RootDocument $ToSave -ParentNode $StigInfoNode -Name "source" -Data $null
    $a = $iSTIGNode.AppendChild($StigInfoNode);

    ##VULN
    foreach ($Vuln in $XCCDFData) {
        $VulnNode = $ToSave.CreateElement("VULN")
        #Set Properties
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Vuln_Num" -Data $Vuln.ID
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Severity" -Data $Vuln.Rule.Severity
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Group_Title" -Data $Vuln.Title
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Rule_ID" -Data $Vuln.Rule.ID
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Rule_Ver" -Data $Vuln.Rule.Version
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Rule_Title" -Data $Vuln.Rule.Title
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Vuln_Discuss" -Data $Vuln.Rule.Description
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "IA_Controls" -Data $Vuln.Rule.IAControls
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Check_Content" -Data $Vuln.Rule.Check.Content
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Fix_Text" -Data $Vuln.Rule.FixText
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "False_Positives" -Data $Vuln.Rule.FalsePositives
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "False_Negatives" -Data $Vuln.Rule.FalseNegatives
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Documentable" -Data $Vuln.Rule.Documentable
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Mitigations" -Data $Vuln.Rule.Mitigations
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Potential_Impact" -Data $Vuln.Rule.PotentialImpacts
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Third_Party_Tools" -Data $Vuln.Rule.ThirdPartyTools
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Mitigation_Control" -Data $Vuln.Rule.MitigationControl
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Responsibility" -Data $Vuln.Rule.Responsibility
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Security_Override_Guidance" -Data $Vuln.Rule.SeverityOverrideGuidance
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Check_Content_Ref" -Data $Vuln.Rule.Check.ContentRefName
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Weight" -Data $Vuln.Rule.Weight
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "Class" -Data $Class
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "STIGRef" -Data ($XCCDFHeadData.Title+" :: "+"Version "+$XCCDFHeadData.Version+", "+$XCCDFHeadData.Release)
        Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "TargetKey" -Data $Vuln.Rule.Reference.Identifier
        foreach ($CCI in (@()+$Vuln.Rule.Ident)) {
            Add-STIGDataNode -RootDocument $ToSave -ParentNode $VulnNode -Name "CCI_REF" -Data $CCI
        }
        Add-XMLTextNode -RootDocument $ToSave -ParentNode $VulnNode -Name "STATUS" -Text "Not_Reviewed"
        Add-XMLTextNode -RootDocument $ToSave -ParentNode $VulnNode -Name "FINDING_DETAILS"
        Add-XMLTextNode -RootDocument $ToSave -ParentNode $VulnNode -Name "COMMENTS"
        Add-XMLTextNode -RootDocument $ToSave -ParentNode $VulnNode -Name "SEVERITY_OVERRIDE"
        Add-XMLTextNode -RootDocument $ToSave -ParentNode $VulnNode -Name "SEVERITY_JUSTIFICATION"
        $a = $iSTIGNode.AppendChild($VulnNode);
    }
    $a = $StigNode.AppendChild($iSTIGNode);
    $a = $ToSave.LastChild.AppendChild($StigNode);
    
    Export-StigCKL -CKLData $ToSave -Path $SaveLocation
}

#endregion

#region CCI Ref Functions
<#
.SYNOPSIS
    Imports the CCIList XML from DISA

.PARAMETER Path
    Path to the CCIList XML

.NOTES
    Downloaded from https://iase.disa.mil/stigs/cci/pages/index.aspx
  
.EXAMPLE
    Import-CCIList -Path "C:\Test\U_CCI_List.xml"
#>
function Import-CCIList
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    return [XML](Get-Content -Path $Path)
}


<#
.SYNOPSIS
    Gets the references for the specified CCI ID (Generally IA Control Policies)

.PARAMETER CCIData
    CCIList data as returned by Import-CCIList

.PARAMETER CCIID
    ID of the CCI to get the references for

.EXAMPLE
    Get-CCIReferences -CCIData $CCIData -CCIID "CCI-000001"
#>
function Get-CCIReferences
{
    Param([Parameter(Mandatory=$true)][xml]$CCIData, [Parameter(Mandatory=$true)][string]$CCIID)
    $ToReturn = @()
    $Definition = (Select-XML -Xml $CCIData -XPath "//*[local-name()='cci_item' and @id='$CCIID']").Node.definition
    $Results = @()+(Select-XML -Xml $CCIData -XPath "//*[local-name()='cci_item' and @id='$CCIID']/*[local-name()='references']/*[local-name()='reference']").Node
    foreach ($Result in $Results) {
        $ToReturn += New-Object -TypeName PSObject -Property @{Title=$Result.Title; Version=$Result.Version; Index=$Result.Index; Location=$Result.Location; Definition=$Definition}
    }
    #Return null on no results
    if ($Results.Count -le 0) {
        return $null
    }
    #Return table of
    return $ToReturn
}

<#
.SYNOPSIS
    Gets the references for the specified CCI IDs associated with the specified VulnID

.PARAMETER CCIData
    CCIList data as returned by Import-CCIList

.PARAMETER CKLData
    CKLData as loaded from the Import-STIGCKL function

.PARAMETER VulnID
    VulnID to get the references for (Do not use with RuleID)

.PARAMETER RuleID
    RuleID to get the references for (Do not use with VulnID)

.EXAMPLE
    Get-CCIVulnReferences -CCIData $CCIData -CKLData $CKLData -VulnID "V-11111"
#>
function Get-CCIVulnReferences {
    Param([Parameter(Mandatory=$true)][xml]$CCIData, [Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, $VulnID, $RuleID)
    $CCIDs = @()+(Get-VulnInfoAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute CCI_REF)
    $Results = @()
    $Keys = @()
    foreach ($CCIID in $CCIDs) {
        $SubResults = Get-CCIReferences -CCIData $CCIData -CCIID $CCIID
        foreach ($Result in $SubResults) {
            $Key = $Result.Title+$Result.Version+$Result.Index
            if (-not $Keys.Contains($Key)) {
                $Keys += $Key
                $Results += $Result
            }
        }
    }
    return $Results
}
#endregion

#Export members
Export-ModuleMember -Function   Get-VulnInfoAttribute, Set-StigDataAttribute, Get-VulnFindingAttribute, Set-VulnFindingAttribute, 
                                Get-VulnIDs, Get-StigAttributeList, Set-VulnCheckResult, Get-VulnCheckResult, Import-StigCKL, 
                                Export-StigCKL, Repair-StigCKL, Get-CKLHostData, Set-VulnCheckResultFromRegistry, Set-CKLHostData, 
                                Merge-CKLData, Merge-CKLs, Import-XCCDF, Get-XCCDFResults, Merge-XCCDFToCKL, Merge-XCCDFHostDataToCKL, 
                                Get-XCCDFHostData, Get-StigMetrics, Get-StigInfoAttribute, Get-XCCDFInfo, Get-XCCDFVulnInformation, 
                                Get-CheckListInfo, Get-CKLVulnInformation, Import-CCIList, Get-CCIReferences, Get-CCIVulnReferences,
                                Get-VulnInformation, Convert-ManualXCCDFToCKL, Get-XCCDFTargetFacts;
