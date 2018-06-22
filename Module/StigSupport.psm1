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
                                                      Release=(Get-StigInfoAttribute -CKLData $CKLData -Attribute "releaseinfo")});
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
    Get-StigAttributeList -CKLData $CKLData
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
        $Details=$null, 
        $Comments=$null,
        [Parameter(Mandatory=$true)][ValidateSet(“Open”,”NotAFinding”,"Not_Reviewed", "Not_Applicable")]$Result
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
  
.EXAMPLE
    Get-VulnCheckResult -CKLData $CKLData -VulnID "V-11111"
#>
function Get-VulnCheckResult
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null, 
        $RuleID=$null
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
        return (New-Object -TypeName PSObject -Property @{Status=$Status;Finding=$Finding;Comments=$Comments; VulnID=$VulnID})
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
            $ToReturn += New-Object -TypeName PSObject -Property @{Status=""+$Status;Finding=""+$Finding;Comments=""+$Comments; VulnID=""+$VulnID}
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
    Load a CKL file as an [XML] element. This can then be passed to other functions in this module.

.PARAMETER Path
    Full path to the CKL file
  
.EXAMPLE
    Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#>
function Import-StigCKL
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    return [XML](Get-Content -Path $Path)
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
        [Parameter(Mandatory=$true)][string]$Path, [switch]$AddHostData
    )
    #Set XML Options to replicate those of the STIG Viewer application
    $XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
    $XMLSettings.Indent = $true;
    $XMLSettings.IndentChars = "    "
    $XMLSettings.NewLineChars="`n"
    #Add Host data if requested
    if ($AddHostData)
    {
        Set-CKLHostData -CKLData $CKLData
    }
    $XMLWriter = [System.XML.XMLTextWriter]::Create($Path, $XMLSettings)
    #Save the data
    $CKLData.Save($XMLWriter)
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
        HostMAC=$CKLData.CHECKLIST.ASSET.HOST_MAC;HostGUID=$CKLData.CHECKLIST.ASSET.HOST_GUID;HostFQDN=$CKLData.CHECKLIST.ASSET.HOST_FQDN}
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
  
.EXAMPLE
    Set-CKLHostData -CKLData $CKLData

.EXAMPLE
    Set-CKLHostData -CKLData $CKLData -Host "SomeMachine" -FQDN "SomeMachine.Some.Domain.com" -Mac "00-00-00-..." -IP "127.0.0.1"
#>
function Set-CKLHostData
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        [string]$Host=(Get-WmiObject -Class Win32_ComputerSystem).Name,
        [string]$FQDN=(Get-WmiObject -Class Win32_ComputerSystem).Name+(Get-WmiObject -Class Win32_ComputerSystem).Domain,
        [string]$Mac=(@()+(Get-WMIObject win32_networkadapterconfiguration | Where-Object -FilterScript {$_.IPAddress -ne $null}))[0].Macaddress,
        [string]$IP=(@()+(Get-WMIObject win32_networkadapterconfiguration | Where-Object -FilterScript {$_.IPAddress -ne $null}))[0].IPAddress[0]
    )
    #Set the various properties
    $CKLData.CHECKLIST.ASSET.HOST_FQDN = $FQDN
    $CKLData.CHECKLIST.ASSET.HOST_IP = $IP
    $CKLData.CHECKLIST.ASSET.HOST_MAC = $Mac
    $CKLData.CHECKLIST.ASSET.HOST_NAME = $Host
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
        [switch]$IncludeNR
    )
    #Get the stig results form the source
    Write-Progress -Activity "Merging" -CurrentOperation "Loading old results"
    $StigResults = Get-VulnCheckResult -CKLData $SourceCKL
    $I=0;
    Write-Progress -Activity "Merging" -CurrentOperation "Writing results" -PercentComplete (($I*100)/$StigResults.Length)
    #Import them into the destination
    foreach ($Result in $StigResults)
    {
        if ($Result.Status -ne "Not_Reviewed" -or $IncludeNR) {
            Set-VulnCheckResult -CKLData $DestinationCKL -VulnID $Result.VulnID -Details $Result.Finding -Comments $Result.Comments -Result $Result.Status
        }
        $I++;
        Write-Progress -Activity "Merging" -PercentComplete (($I*100)/$StigResults.Length)
    }
    #Copy over host info
    $HostInfo = Get-CKLHostData -CKLData $SourceCKL
    Set-CKLHostData -CKLData $DestinationCKL -Host $HostInfo.HostName -FQDN $HostInfo.HostFQDN -Mac $HostInfo.HostMAC -IP $HostInfo.HostIP
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
  
.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl"

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
        [switch]$IncludeNR
    )
    #Load both inputs
    $DestinationCKL = Import-StigCKL -Path $DestinationCKLFile
    $SourceCKL = Import-StigCKL -Path $SourceCKLFile
    #Merge 'em
    Merge-CKLData -SourceCKL $SourceCKL -DestinationCKL $DestinationCKL -IncludeNR:$IncludeNR
    #Save output
    Export-StigCKL -CKLData $DestinationCKL -Path $SaveFilePath
}

<#
.SYNOPSIS
    Returns a complex object of metrics on the statuses of the checks.

.PARAMETER CKLDirectory
    Path to folder container the ckls to pull metrics on
  
.EXAMPLE
    Get-StigMetrics -CKLDirectory "C:\CKLS\"
#>
function Get-StigMetrics
{
    Param($CKLDirectory)
    #AllChecklists
    $CKFiles = Get-ChildItem -Path $CKLDirectory -Filter "*.ckl" -Recurse
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
    return [XML](Get-Content -Path $Path)
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
  
.EXAMPLE
    Merge-XCCDFToCKL -CKLData $CKLData -XCCDF $XCCDFData
#>
function Merge-XCCDFToCKL
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, 
        [Parameter(Mandatory=$true)][xml]$XCCDF
    )
    #Grab the results from the XCCDF Data
    $Results = Get-XCCDFResults -XCCDF $XCCDF
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
        #Set it in the CKL
        Set-VulnCheckResult -CKLData $CKLData -RuleID $Result.RuleID -Result $Res -Details "Checked by SCAP tool" -Comments "Checked by SCAP tool, imported into CKL by StigSupportFunctions.psm1"
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
  
.EXAMPLE
    Get-XCCDFHostData -XCCDF $XCCDFData
#>
function Get-XCCDFHostData
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF)

    #Pre fill variables
    $HostName, $HostIP, $HostMAC, $HostGUID, $HostFQDN = ""
    #Load info
    $HostName = $XCCDF.Benchmark.TestResult.target
    $HostIP = (@()+$XCCDF.Benchmark.TestResult.'target-address')[0]
    $HostMAC = (@()+($XCCDF.Benchmark.TestResult.'target-facts'.fact | Where-Object {$_.name -eq "urn:scap:fact:asset:identifier:mac"}).'#text')[0]
    $HostFQDN = (@()+($XCCDF.Benchmark.TestResult.'target-facts'.fact | Where-Object {$_.name -eq "urn:scap:fact:asset:identifier:fqdn"}).'#text')[0]
    $HostGUID = (@()+($XCCDF.Benchmark.TestResult.'target-facts'.fact | Where-Object {$_.name -eq "urn:scap:fact:asset:identifier:guid"}).'#text')[0]
    #Return host info
    return (New-Object -TypeName PSObject -Property @{HostName=$HostName;HostIP=$HostIP;HostMac=$HostMAC;HostFQDN=$HostFQDN;HostGUID=$HostGUID})
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
    return (New-Object -TypeName PSObject -Property @{Title=$XCCDF.Benchmark.title;Description=$XCCDF.Benchmark.description;Release=$Version})
}

<#
.SYNOPSIS
    Returns an array of the vulns in the xccdf file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-XCCDF
  
.EXAMPLE
    Get-XCCDFVulnInformation -XCCDF $XCCDFData
#>
function Get-XCCDFVulnInformation {
    Param([Parameter(Mandatory=$true)][xml]$XCCDF)
    $Results = @()
    $Groups = $XCCDF.Benchmark.Group
    foreach ($Group in $Groups) {
        $Description = $Group.Rule.description;
        #Description is weird, it is like further XML, but encoded and not as separate elements. idk, but this regex will extract what we want out of the mess
        if ($Description -match "<VulnDiscussion\>([\w\W]*)</VulnDiscussion>") {
            $Description = $Matches[1]
        }
        $Results += New-Object -TypeName PSObject -Property @{ID=$Group.id;Title=$Group.Rule.Title;Version=$Group.Rule.Version;Description=$Description;FixText=$Group.Rule.fixtext.'#text';CheckText=$Group.Rule.check.'check-content'}
    }
    return $Results
}
#endregion

#region CCI Functions
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
                                Get-CheckListInfo, Get-CKLVulnInformation, Import-CCIList, Get-CCIReferences, Get-CCIVulnReferences;