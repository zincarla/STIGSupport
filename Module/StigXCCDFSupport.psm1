#region XCCDF Functions 
<#
.SYNOPSIS
    Load an XCCDF file

.PARAMETER Path
    Path to the XCCDF file
  
.EXAMPLE
    Import-StigXCCDF -Path C:\XCCDF\Results.xml
#>
function Import-StigXCCDF
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    $ToReturn = [XML](Get-Content -Encoding UTF8 -Path $Path)
    if ($ToReturn.benchmark.cdf -ne "http://checklists.nist.gov/xccdf/1.2"){
        Write-Warning "This module was not designed or tested against this file's format and may not function correctly."
    }
    return $ToReturn
}

<#
.SYNOPSIS
    Returns stig results from an XCCDF file

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-StigXCCDF
  
.EXAMPLE
    Get-StigXCCDFResults -XCCDF (Import-XCCDF -Path C:\XCCDF\Results.xml)
#>
function Get-StigXCCDFResults
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
    Gets host info from XCCDF

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-StigXCCDF

.PARAMETER Filter
    If provided, this will be used to select a specific IP/MAC pair from the XCCDF file. Consider filtering on interface_name, ipv4 or mac and check for nulls

.EXAMPLE
    Get-StigXCCDFHostData -XCCDF $XCCDFData

.EXAMPLE
    Get-StigXCCDFHostData -XCCDF $XCCDFData -Filter {$_.ipv4 -ne $null -and $_.ipv4 -like "192.133.*"}
#>
function Get-StigXCCDFHostData
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF, [scriptblock]$Filter)

    #Init variables with empty string
    $HostName, $HostIP, $HostMAC, $HostGUID, $HostFQDN = ""
    #Load info
    $Facts = Get-StigXCCDFTargetFacts -XCCDF $XCCDF
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
    XCCDF data as loaded from the Import-StigXCCDF
  
.EXAMPLE
    Get-StigXCCDFTargetFacts -XCCDF $XCCDFData
#>
function Get-StigXCCDFTargetFacts
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
    XCCDF data as loaded from the Import-StigXCCDF
  
.EXAMPLE
    Get-StigXCCDFInfo -XCCDF $XCCDFData
#>
function Get-StigXCCDFInfo
{
    Param([Parameter(Mandatory=$true)][xml]$XCCDF)
    $Version = ($XCCDF.Benchmark.'plain-text' | Where-Object {$_.id -eq 'release-info'}).'#text'
    return (New-Object -TypeName PSObject -Property @{Title=$XCCDF.Benchmark.title;Description=$XCCDF.Benchmark.description;Release=$Version; Version=$XCCDF.Benchmark.version; ID = $XCCDF.Benchmark.id})
}

<#
.SYNOPSIS
    Returns an array of the vulns in the xccdf file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-StigXCCDF

.PARAMETER Full
    If supplied, will pull all information in a less friendly format.
  
.EXAMPLE
    Get-StigXCCDFVulnInformation -XCCDF $XCCDFData

.EXAMPLE
    Get-StigXCCDFVulnInformation -XCCDF $XCCDFData -Full
#>
function Get-StigXCCDFVulnInformation {
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

#endregion

#region CKLB Functions

<#
.SYNOPSIS
    Internal function to loosely verify user is attempting to read/manipulate a variable with loaded CKLB data.

.PARAMETER CKLBData
    CKLBData as loaded from Import-StigCKLBFile
  
.EXAMPLE
    Validate-StigCKLBParam CKLBData $CKLBData
#>
function Validate-StigCKLBParam {
    param($CKLBData)
    return ($CKLBData.stigs -ne $null)
}

<#
.SYNOPSIS
    Adds XCCDF results into a loaded CKL data

.PARAMETER CKLBData
    CKLB Data as loaded by Import-StigCKLBFile

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-StigXCCDF

.PARAMETER NoCommentsOnOpen
    Will not write custom comments over previous comments if the check is open
  
.EXAMPLE
    Merge-StigXCCDFToCKLB -CKLBData $CKLBData -XCCDF $XCCDFData
#>
function Merge-StigXCCDFToCKLB
{
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData, 
        [Parameter(Mandatory=$true)][xml]$XCCDF,
        [switch]$NoCommentsOnOpen
    )
    if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigCKLBSupport"}).Count -le 0)
    {
        #End if not
        Write-Error "Please import StigCKLBSupport.psm1 before running this function"
        return
    }
    #Grab the results from the XCCDF Data
    $Results = Get-StigXCCDFResults -XCCDF $XCCDF
    $PrevResults = $null
    if ($NoCommentsOnOpen) {
        $PrevResults = Get-StigCKLBRuleInfo -CKLBData $CKLBData -All
    }
    $I=0;
    Write-Progress -Activity "Importing" -PercentComplete (($I*100)/$Results.Count)
    #Loop through them
    foreach ($Result in $Results)
    {
        #Convert result to CKL result
        $Res = "open"
        if ($Result.result -eq "pass")
        {
            $Res = "not_a_finding"   
        }

        $Details = "Checked by SCAP tool"
        $Comments = "Checked by SCAP tool"
        
        if ($NoCommentsOnOpen) {
            $PrevResult = $PrevResults | Where-Object {$_.rule_id -eq $Result.RuleID}
            if ($PrevResult -ne $null -and $PrevResult.Status -ne "not_a_finding") {
                $Details = $PrevResult.finding_details
                $Comments = $PrevResult.comments
            }
        }

        #Set it in the CKL
        Set-StigCKLBRuleFinding -CKLBData $CKLBData -RuleID $Result.RuleID -Result $Res -FindingDetails $Details -Comments $Comments 
        $I++;
        Write-Progress -Activity "Importing" -PercentComplete (($I*100)/$Results.Count)
    }
    #Add machine into from XCCDF
    Merge-StigXCCDFHostDataToCKLB -CKLBData $CKLBData -XCCDF $XCCDF
    Write-Progress -Activity "Importing" -PercentComplete 100 -Completed
}

<#
.SYNOPSIS
    Adds XCCDF host info into loaded CKLB data

.PARAMETER CKLBData
    CKLB Data as loaded by Import-StigCKLBFile

.PARAMETER XCCDF
    XCCDF data as loaded from the Import-StigXCCDF
  
.EXAMPLE
    Merge-StigXCCDFHostDataToCKLB -CKLBData $CKLBData -XCCDF $XCCDFData
#>
function Merge-StigXCCDFHostDataToCKLB
{
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData,
        [Parameter(Mandatory=$true)][xml]$XCCDF
    )
    if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigCKLBSupport"}).Count -le 0)
    {
        #End if not
        Write-Error "Please import StigCKLBSupport.psm1 before running this function"
        return
    }
    #Get machine info
    $MachineInfo = Get-StigXCCDFHostData -XCCDF $XCCDF
    #Add it to CKL
    Set-StigCKLBTargetData -CKLBData $CKLBData -HostName $MachineInfo.HostName -IP $MachineInfo.HostIP -Mac $MachineInfo.HostMAC -FQDN $MachineInfo.HostFQDN
}

#endregion


Export-ModuleMember -Function Import-StigXCCDF, Get-StigXCCDFResults, Get-StigXCCDFHostData, Get-StigXCCDFTargetFacts, Get-StigXCCDFInfo, Get-StigXCCDFVulnInformation,
                                Merge-StigXCCDFToCKLB, Merge-StigXCCDFHostDataToCKLB