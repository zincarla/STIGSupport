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
    Loads a CKLB file as an [PSCustomObject]. This can then be passed to other functions in this module.

.PARAMETER Path
    Full path to the CKLB file
  
.EXAMPLE
    Import-StigCKLBFile -Path "C:\CKLBs\MyCKL.cklb"
#>
function Import-StigCKLBFile {
    Param([Parameter(Mandatory=$true)][ValidateScript({(Test-Path -Path $_) -and $_ -like "*.cklb"})][string]$Path)
    $ToReturn = (Get-Content -Path $Path -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
    if ($ToReturn -eq $null) {
        throw "Invalid CKLB file."
    } elseif ($ToReturn.cklb_version -ne "1.0" -and $ToReturn.cklb_version -ne $null) {
        Write-Warning "This module is not confirmed to work with this CKLB file's version"
    }
    return $ToReturn
}

<#
.SYNOPSIS
    Saves a loaded CKLB file to disk

.PARAMETER CKLData
    The loaded CKLB Data as loaded by Import-StigCKLBFile

.PARAMETER Path
    Full path to the CKLB file

.PARAMETER AddHostData
    Automatically adds the running hosts information into the CKLB before saving

.EXAMPLE
    Export-StigCKLBFile -CKLBData $CKLBData -Path "C:\CKLBs\MyCKL.cklb"

.EXAMPLE
    Export-StigCKLBFile -CKLBData $CKLBData -Path "C:\CKLBs\MyNewCKL.cklb" -AddHostData
#>
function Export-StigCKLBFile {
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData, 
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$AddHostData
    )
    #Add Host data if requested
    if ($AddHostData)
    {
        Set-CKLBHostData -CKLData $CKLData -AutoFill
    }
    $CKLBData | ConvertTo-Json -Depth 99 -Compress | Out-File -FilePath $Path -Encoding utf8
}

<#
.SYNOPSIS
    Sets target data (host) in CKLB. (Previously Set-CKLHostData)

.PARAMETER CKLBData
    CKLB Data as loaded by Import-StigCKLBFile

.PARAMETER Host
    Short host name

.PARAMETER FQDN
    Fully qualified domain name

.PARAMETER Mac
    Mac of the host

.PARAMETER IP
    IP address of the host

.PARAMETER TargetComments
    Comments of the target

.PARAMETER TargetCommentsFromAD
    Fills target comments from the machines AD description, if exists and found.

.PARAMETER IsWebOrDB
    Manually selects the Web or DB STIG setting. This is auto-set to true if webdbsite or webdbinstance is provided while this is $null

.PARAMETER WebDBSite
    Sets the web or db site STIG for the CKL. Will autoset IsWebOrDB to true if this is provided and IsWebOrDB is not.

.PARAMETER TechnologyArea
    Sets the TechnologyArea field.

.PARAMETER TargetType
    Sets TargetType field.
  
.EXAMPLE
    Set-StigCKLBTargetData -CKLBData $CKLBData -AutoFill

.EXAMPLE
    Set-StigCKLBTargetData -CKLBData $CKLBData -Host "SomeMachine" -FQDN "SomeMachine.Some.Domain.com" -Mac "00-00-00-..." -IP "127.0.0.1"
#>
function Set-StigCKLBTargetData {
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData,
        $HostName,
        $FQDN,
        $Mac,
        $IP,
        $TargetComments,
        $WebDBSite,
        $WebDBInstance,
        $TechnologyArea,
        $TargetType,
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
        if ($HostName -eq $null) {
            $HostName = (Get-WmiObject -Class Win32_ComputerSystem).Name
        }
        if ($FQDN -eq $null) {
            $FQDN = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $HostName).Name+"."+(Get-WmiObject -Class Win32_ComputerSystem -ComputerName $HostName).Domain
        }
        if ($Mac -eq $null) {
            $Mac = (@()+(Get-WMIObject win32_networkadapterconfiguration -ComputerName $HostName | Where-Object -FilterScript {$_.IPAddress -ne $null}))[0].Macaddress
        }
        if ($IP -eq $null) {
            $IP = (@()+(Get-WMIObject win32_networkadapterconfiguration -ComputerName $HostName | Where-Object -FilterScript {$_.IPAddress -ne $null}))[0].IPAddress[0]
        }
        if ($Role -eq $null) {
            $Role = "None"
            $PType = (Get-WmiObject -Class Win32_OperatingSystem -Property ProductType -ComputerName $HostName).ProductType
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
    if ($HostName -ne $null) {
        $CKLBData.target_data.host_name = $HostName.ToString()
    }
    if ($FQDN -ne $null) {
        $CKLBData.target_data.fqdn = $FQDN.ToString()
    }
    if ($IP -ne $null) {
        $CKLBData.target_data.ip_address = $IP.ToString()
    }
    if ($Mac -ne $null) {
        $CKLBData.target_data.mac_address = $Mac.ToString()
    }
    if ($Role -ne $null) {
        $CKLBData.target_data.role = $Role.ToString()
    }
    if ($TargetComments -ne $null) {
        $CKLBData.target_data.comments = $TargetComments.ToString()
    }
    if ($IsWebOrDB -eq $null -and ($WebDBSite -ne $null -or $WebDBInstance -ne $null)) {
        $CKLBData.target_data.is_web_database = "True"
    } elseif ($IsWebOrDB -ne $null) {
        $CKLBData.target_data.is_web_database = $IsWebOrDB.ToString().ToUpper()
    }
    if ($WebDBSite -ne $null) {
        $CKLBData.target_data.web_db_site = $WebDBSite.ToString()
    }
    if ($WebDBInstance -ne $null) {
        $CKLBData.target_data.web_db_instance = $WebDBInstance.ToString()
    }
    if ($TechnologyArea -ne $null) {
        $CKLBData.target_data.technology_area = $TechnologyArea.ToString()
    }
    if ($TargetType -ne $null) {
        $CKLBData.target_data.target_type = $TargetType.ToString()
    }
}

<#
.SYNOPSIS
    Gets the host information from the CKLBData

.PARAMETER CKLData
    CKLB Data as loaded by Import-StigCKLBFile
  
.EXAMPLE
    Get-StigCKLBTargetData -CKLBData $CKLBData
#>
function Get-StigCKLBTargetData {
    Param([Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData)
    # Mostly for people expecting a get-host style function
    #Return cloned object to prevent accidental editing
    return ([System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($CKLBData.target_data)));
}

<#
.SYNOPSIS
    Returns a specified stig attribute. This contains general information on the STIG file itself. (stig_name, display_name, release_info) (replaces Get-CKLStigAttribute from old module)

.PARAMETER CKLBData
    Data as return from the Import-StigCKLBFile

.PARAMETER Attribute
    The Attribute you want returned

.PARAMETER StigID
    CKLB files may contain multiple STIGs. A stig ID is required to select a specific one.
  
.EXAMPLE
    Get-StigCKLBStigAttribute -CKLBData $CKLBData -Attribute "Version" -StigID "Microsoft_Windows_11_STIG"
#>
function Get-StigCKLBStigAttribute {
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData,
        [Parameter(Mandatory=$true)]$Attribute,
        [Parameter(Mandatory=$true)]$StigID
    )
    #What we will return
    $ToReturn = $CKLBData.stigs | where-object {$_.stig_id -eq $StigID}
    if ($ToReturn -eq $null) {
        Write-Error "Specified StigID ($StigID) was not found in CKLB"
    }

    $PropertyInfo = $ToReturn | Get-Member -Name $Attribute

    #Write error if the attribute was not found
    if ($PropertyInfo -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found"
    }
    return $ToReturn.$Attribute
}

<#
.SYNOPSIS
    Gets general info from the checklist about the STIGs contained (release_info, stig_name, stig_id) (Replaces Get-CKLStigInfo from old module)

.PARAMETER CKLBData
    CKLB data as loaded from the Import-StigCKLBFile
  
.EXAMPLE
    Get-StigCKLBStigInfo -CKLBData $CKLBData
#>
function Get-StigCKLBStigInfo {
    Param([Parameter(Mandatory=$true,ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData)
    $StigData = @()

    foreach ($Stig in $CKLBData.stigs) {
        $StigData+=New-Object -TypeName PSObject -Property @{stig_name=$Stig.stig_name;
            release_info=$Stig.release_info;
            stig_id=$Stig.stig_id;        
        };
    }
    return $StigData
}

<#
.SYNOPSIS
    Returns all VulnIDs (group_id) contained in the CKLB (Replaces Get-CKLVulnIDs from old module)

.PARAMETER CKLBData
    Data as return from the Import-StigCKLBFile
  
.EXAMPLE
    Get-StigCKLBVulnIDs -CKLBData $CKLBData
#>
function Get-StigCKLBVulnIDs {
    Param([Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData)
    #Return an array of all VulnIDs
    $ToReturn = @()
    foreach ($Stig in $CKLBData.stigs) {
        foreach ($Rule in $Stig.rules) {
            $ToReturn += $Rule.group_id
        }
    }
    return $ToReturn
}

<#
.SYNOPSIS
    Returns all RuleIDs (rule_id) contained in the CKLB

.PARAMETER CKLBData
    Data as return from the Import-StigCKLBFile
  
.EXAMPLE
    Get-StigCKLBRuleIDs -CKLBData $CKLBData
#>
function Get-StigCKLBRuleIDs {
    Param([Parameter(Mandatory=$true, ValueFromPipeline = $true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$CKLBData)
    #Return an array of all RuleIDs
    $ToReturn = @()
    foreach ($Stig in $CKLBData.stigs) {
        foreach ($Rule in $Stig.rules) {
            $ToReturn += $Rule.rule_id
        }
    }
    return $ToReturn
}

<#
.SYNOPSIS
    Returns all Rules contained in the CKLB (All properties such as check text and current findings). From the old module, this effectively replaces Get-VulnInfoAttribute, Get-VulnFindingAttribute, Get-CKLVulnInformation, Get-CKLVulnCheckResult and Get-VulnInformation

.PARAMETER CKLBData
    Data as return from the Import-StigCKLBFile
  
.EXAMPLE
    Get-StigCKLBRuleInfo -CKLBData $CKLBData -VulnID "V-#####"

.EXAMPLE
    Get-StigCKLBRuleInfo -CKLBData $CKLBData -RuleID "SV-#####"
#>
function Get-StigCKLBRuleInfo {
    [alias("Get-VulnInfo")]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'Vuln')]
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'Rule')]
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'All')]
        [ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]
        $CKLBData,
        [Parameter(Mandatory=$true, ParameterSetName = 'Rule')][string]$RuleID,
        [Parameter(Mandatory=$true, ParameterSetName = 'Vuln')][string]$VulnID,
        [Parameter(Mandatory=$true, ParameterSetName = 'All')][switch]$All
    )
    #Replaces Get-VulnInfoAttribute, Get-VulnFindingAttribute, Get-CKLVulnInformation, Get-CKLVulnCheckResult, Get-VulnInformation

    #Return result for single Rule
    if (-not $All) {
        $SourceRule = $null
        #Scan through all stigs searching for the specified rule/vuln
        foreach ($Stig in $CKLBData.stigs) {
            $Search = $null
            if ($VulnID -ne $null) {
                $Search = $Stig.rules | Where-Object {$_.group_id -eq $VulnID}
            } else {
                $Search = $Stig.rules | Where-Object {$_.rule_id -eq $RuleID}
            }
            if ($Search -ne $null) {
                $SourceRule=$Search
                break
            }
        }

        if ($SourceRule -eq $null) {
            throw "Rule matching the given Vuln or Rule ID was not found"
        }

        # Return a cloned object to prevent unintended changes to loaded CKLB data
        return ([System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($SourceRule)));
    } else {
        #Return all
        $ToReturn = @()
        #Scan through all stigs
        foreach ($Stig in $CKLBData.stigs) {
            foreach ($SourceRule in $Stig.rules) {
                $ToReturn+=[System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($SourceRule));
            }
        }
        return $ToReturn;
    }
}

<#
.SYNOPSIS
    Sets a rule/vuln status, comment, details, and override options. (Replaces Set-VulnFindingAttribute and Set-VulnCheckResult from old module)

.PARAMETER CKLBData
    Data as return from the Import-StigCKLBFile

.PARAMETER FindingDetails
    Details about a finding's status (If null, no change is made to this property)

.PARAMETER Comments
    Comments about a finding's status (If null, no change is made to this property)

.PARAMETER Status
    The status of this finding (If null, no change is made to this property)

.PARAMETER VulnID
    VulnID of the status to set (Required if RuleID is not provided)

.PARAMETER RuleID
    RuleID of the status to set (Required if VulnID is not provided)

.PARAMETER OverrideSeverity
    Overriddes the severity of a finding (Must be set with OverrideSeverityJustification)

.PARAMETER OverrideSeverityJustification
    Justification of the severity override (Must be set with OverrideSeverity)

.EXAMPLE
    Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID "V-#####" -Status "not_a_finding" -FindingDetails "All good" -Comments "Nothing to see here"

.EXAMPLE
    Set-StigCKLBRuleFinding -CKLBData $CKLBData -RuleID "SV-#####" -Status "open" -FindingDetails "Its set wrong" -Comments "This was set wrong" -OverrideSeverity "low" -OverrideSeverityJustification "Because I said so"
#>
function Set-StigCKLBRuleFinding {
    [alias("Set-StigCKLBVulnFinding")]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'Vuln')]
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'Rule')]
        [ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]
        $CKLBData,
        [Parameter(Mandatory=$true, ParameterSetName = 'Rule')][string]$RuleID,
        [Parameter(Mandatory=$true, ParameterSetName = 'Vuln')][string]$VulnID,
        $FindingDetails,
        $Comments,
        [Alias("Result")]
        [ValidateSet("open","not_a_finding","not_reviewed", "not_applicable", $null)]
        $Status,
        [ValidateSet("low","medium","high", $null)]
        $OverrideSeverity,
        $OverrideSeverityJustification
    )
    if ($OverrideSeverity -ne $null -and [String]::IsNullOrWhiteSpace($OverrideSeverityJustification)) {
        throw "Severity override requires a justification"
    }
    if ($OverrideSeverity -eq $null -and $OverrideSeverityJustification -ne $null) {
        throw "Severity Justification must be set in tandem with a Severity Override"
    }
    if ($OverrideSeverity -ne $null) {
        $OverrideSeverity = $OverrideSeverity.ToLower()
    }
    if ($Status -ne $null) {
        $Status = $Status.ToLower()
    }

    $SourceRule = $null
    #Scan through all stigs searching for the specified rule/vuln
    foreach ($Stig in $CKLBData.stigs) {
        $Search = $null
        if ($VulnID -ne $null) {
            $Search = $Stig.rules | Where-Object {$_.group_id -eq $VulnID}
        } else {
            $Search = $Stig.rules | Where-Object {$_.rule_id -eq $RuleID}
        }
        if ($Search -ne $null) {
            $SourceRule=$Search
            break
        }
    }
    if ($SourceRule -eq $null) {
        throw "Rule matching the given Vuln or Rule ID was not found"
    }

    if ($Comments -ne $null) {
        $SourceRule.comments = $Comments.ToString()
    }
    if ($FindingDetails -ne $null) {
        $SourceRule.finding_details = $FindingDetails.ToString()
    }
    if ($Status -ne $null) {
        $SourceRule.status = $Status
    }
    if ($OverrideSeverity -ne $null) {
        $HasSeverity = $SourceRule.overrides | Get-Member -Name "severity"
        if ($HasSeverity) {
            $SourceRule.overrides.severity.severity = $OverrideSeverity
            $SourceRule.overrides.severity.reason = $OverrideSeverityJustification
        } else {
            $SourceRule.overrides | Add-Member -MemberType NoteProperty -Name "severity" -Value (New-Object -TypeName PSObject -Property @{"severity"=$OverrideSeverity; "reason"=$OverrideSeverityJustification})
        }
    }
}

<#
.SYNOPSIS
    Sets a rule/vuln status based on a registry check (Replaces Set-VulnCheckResultFromRegistry from old module)

.PARAMETER CKLBData
    CKLB Data as loaded by Import-StigCKLBFile

.PARAMETER VulnID
    ID Of the STIG check to set (Required if RuleID is not provided)

.PARAMETER RuleID
    ID Of the STIG check to set (Required if VulnID is not provided)

.PARAMETER RegKeyPath
    Path to the registry key

.PARAMETER RequiredKey
    Key name

.PARAMETER RequiredValue
    Value the key should be to pass check

.PARAMETER Comments
    Value to set Comments to
  
.EXAMPLE
    Set-StigCKLBRuleStatusFromRegistry -CKLBData $CKLBData -RegKeyPath "HKLM:\SOFTWARE\COMPANY\DATA" -RequiredKey "PortStatus" -RequiredValue "Closed" -Comments "Checked by asdf"
#>
function Set-StigCKLBRuleStatusFromRegistry {
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'Vuln')]
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ParameterSetName = 'Rule')]
        [ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]
        $CKLBData,
        [Parameter(Mandatory=$true, ParameterSetName = 'Rule')][string]$RuleID,
        [Parameter(Mandatory=$true, ParameterSetName = 'Vuln')][string]$VulnID,
        [Parameter(Mandatory=$true)][string]$RegKeyPath,
        [Parameter(Mandatory=$true)][string]$RequiredKey,
        [Parameter(Mandatory=$true)]$RequiredValue,
        $Comments
    )
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
            if ($VulnID -ne $null){
                Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID:$VulnID -FindingDetails $Details -Comments:$Comments -Status "not_a_finding"
            } elseif ($RuleID -ne $null) {
                Set-StigCKLBRuleFinding -CKLBData $CKLBData -RuleID:$RuleID -FindingDetails $Details -Comments:$Comments -Status "not_a_finding"
            }
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
            if ($VulnID -ne $null){
                Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID:$VulnID -FindingDetails $Details -Comments:$Comments -Status "open"
            } elseif ($RuleID -ne $null) {
                Set-StigCKLBRuleFinding -CKLBData $CKLBData -RuleID:$RuleID -FindingDetails $Details -Comments:$Comments -Status "open"
            }
        }
    }
    else
    {
        #If not, set the check to failed
        $Details = "Required key path $RegKeyPath does not exist"
        if ($VulnID -ne $null){
            Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID:$VulnID -FindingDetails $Details -Comments:$Comments -Status "open"
        } elseif ($RuleID -ne $null) {
            Set-StigCKLBRuleFinding -CKLBData $CKLBData -RuleID:$RuleID -FindingDetails $Details -Comments:$Comments -Status "open"
        }
    }
}

<#
.SYNOPSIS
    Returns a complex object of metrics on the statuses of the checks in a directory of checklists, or a checklist (Replaces Get-StigMetrics)

.PARAMETER Path
    Path to folder container the cklbs to pull metrics on
  
.EXAMPLE
    Get-StigCKLBMetrics -Path "C:\CKLBs\"
#>
function Get-StigCKLBMetrics {
    Param([Alias("CKLBDirectory")]$Path)

    if ((Get-Item $Path) -is [system.io.fileinfo] -and $Path -like "*.cklb") {
        $CKFiles = @()+(Get-Item $Path)
    } else {
        #AllChecklists
        $CKFiles = Get-ChildItem -Path $Path -Filter "*.cklb" -Recurse
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
        Write-Host "$($CKL.FullName)"
        $CKLData = Import-StigCKLBFile -Path $CKL.FullName
        $Results = Get-StigCKLBRuleInfo -CKLBData $CKLData -All
        #Add to grand totals
        $Open+= (@()+($Results | Where-Object {$_.Status -eq "open"})).Count
        $NAF+= (@()+($Results | Where-Object {$_.Status -eq "not_a_finding"})).Count
        $NA+= (@()+($Results | Where-Object {$_.Status -eq "not_applicable"})).Count
        $NR+= (@()+($Results | Where-Object {$_.Status -eq "not_reviewed"})).Count
        #Add to sub totals
        foreach ($Stig in $Results)
        {
            #Convert Cat to match table
            $Cat = $Stig.severity
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
            if (-not $IndividualStigs.ContainsKey($Stig.group_id)) {
                $IndividualStigs += @{$Stig.group_id=(New-Object -TypeName PSObject -Property @{VulnID=$Stig.group_id; Open=0; NotApplicable = 0; NotAFinding=0; NotReviewed=0; Category=$Cat})}
                $Categories[$Cat].UniqueTotal += 1;
            }
            #Track it
            if ($Stig.Status -eq "open") {
                $IndividualStigs[$Stig.group_id].Open++;
                $Categories[$Cat].Open += 1;
            } elseif ($Stig.Status -eq "not_applicable") {
                $IndividualStigs[$Stig.group_id].NotApplicable++;
                $Categories[$Cat].NotApplicable += 1;
            } elseif ($Stig.Status -eq "not_a_finding") {
                $IndividualStigs[$Stig.group_id].NotAFinding++;
                $Categories[$Cat].NotAFinding += 1;
            } elseif ($Stig.Status -eq "not_reviewed") {
                $IndividualStigs[$Stig.group_id].NotReviewed++;
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

<#
.SYNOPSIS
    Merges two loaded CKLBs (Replaces Marge-CKLData from old module)

.PARAMETER SourceCKLB
    The CKL that contains the data to merge, as from Import-StigCKL

.PARAMETER DestinationCKLB
    The CKL that the data should merge into, as from Import-StigCKL

.PARAMETER IncludeNR
    If this is set, Items marks at "Not_Reviewed" will overwrite the destination, otherwise only answered items are merged
  
.EXAMPLE
    Merge-StigCKLBData -SourceCKLB $OriginalInfo -DestinationCKLB $NewCKLB
#>
function Merge-StigCKLBData {
    Param
    (
        [Parameter(Mandatory=$true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$SouceCKLB,
        [Parameter(Mandatory=$true)][ValidateScript({(Validate-StigCKLBParam -CKLBData $_)})]$DestinationCKLB,
        [switch]$IncludeNR,
        [switch]$DontCopyHostInfo,
        [switch]$DontOverwriteVulns
    )

    #Get the stig results form the source
    Write-Progress -Activity "Merging" -CurrentOperation "Loading old results"
    $StigResults = Get-StigCKLBRuleInfo -CKLBData $SouceCKLB -All
    $DestinationIDs = (Get-StigCKLBRuleInfo -CKLBData $DestinationCKLB -All).group_id
    $I=0;
    Write-Progress -Activity "Merging" -CurrentOperation "Writing results" -PercentComplete (($I*100)/$StigResults.Length)
    #Import them into the destination
    foreach ($Result in $StigResults)
    {
        if ($DestinationIDs.Contains($Result.group_id)) {
            if ($Result.status -ne "not_reviewed" -or $IncludeNR) {
                if ($DontOverwriteVulns) {
                    $PrevResult = Get-StigCKLBRuleInfo -CKLBData $DestinationCKLB -VulnID $Result.group_id
                    if ($PrevResult -eq $null -or $PrevResult.Status -eq "not_reviewed") {
                        Set-StigCKLBRuleFinding -CKLBData $DestinationCKLB -VulnID $Result.group_id -FindingDetails $Result.finding_details -Comments $Result.comments -Status $Result.status
                    }
                }
                else
                {
                    Set-StigCKLBRuleFinding -CKLBData $DestinationCKLB -VulnID $Result.group_id -FindingDetails $Result.finding_details -Comments $Result.Comments -Status $Result.Status
                }
            }
        } else {
            Write-Warning "$($Result.group_id) does not exist in the destination. Maybe removed in a newer version?"
        }
        $I++;
        Write-Progress -Activity "Merging" -PercentComplete (($I*100)/$StigResults.Length)
    }
    #Copy over host info
    if (-not $DontCopyHostInfo) {
        $DestinationCKLB.target_data.target_type = $SouceCKLB.target_data.target_type
        $DestinationCKLB.target_data.host_name = $SouceCKLB.target_data.host_name
        $DestinationCKLB.target_data.ip_address = $SouceCKLB.target_data.ip_address
        $DestinationCKLB.target_data.mac_address = $SouceCKLB.target_data.mac_address
        $DestinationCKLB.target_data.fqdn = $SouceCKLB.target_data.fqdn
        $DestinationCKLB.target_data.comments = $SouceCKLB.target_data.comments
        $DestinationCKLB.target_data.role = $SouceCKLB.target_data.role
        $DestinationCKLB.target_data.is_web_database = $SouceCKLB.target_data.is_web_database
        $DestinationCKLB.target_data.technology_area = $SouceCKLB.target_data.technology_area
        $DestinationCKLB.target_data.web_db_site = $SouceCKLB.target_data.web_db_site
        $DestinationCKLB.target_data.web_db_instance = $SouceCKLB.target_data.web_db_instance
    }
    Write-Progress -Activity "Merging" -PercentComplete 100 -Completed
}


<#
.SYNOPSIS
    Merges two CKLB files and saves it as a new CKLB. Largely a wrapper around Merge-StigCKLBData. (Replaces Merge-CKLs in old module)

.PARAMETER SourceCKLBFile
    The CKLB file path that contains the data to merge

.PARAMETER DestinationCKLBFile
    The CKLB file path that the data should merge into

.PARAMETER IncludeNR
    If this is set, Items marked as "not_reviewed" will overwrite the destination, otherwise only answered items are merged
  
.PARAMETER DontCopyHostInfo
    Does not overwrite desination's host data

.PARAMETER DontOverwriteVulns
    Does not overwrite desination's vuln findings. Result is only not_reviewed checks are filled.
  
.EXAMPLE
    Merge-StigCKLBFiles -DestinationCKLBFile "C:\CKLS\Blank.cklb" -DestinationCKLBFile "C:\CKLS\Answered.cklb" -SaveFilePath "C:\CKLS\Merged.cklb"

.EXAMPLE
    Merge-StigCKLBFiles -DestinationCKLBFile "C:\CKLS\ManualChecks.cklb" -DestinationCKLBFile "C:\CKLS\ScapResults.cklb" -SaveFilePath "C:\CKLS\MergedChecks.cklb" -DontCopyHostInfo -DontOverwriteVulns

.EXAMPLE
    Merge-StigCKLBFiles -DestinationCKLBFile "C:\CKLS\Blank.cklb" -DestinationCKLBFile "C:\CKLS\Answered.cklb" -SaveFilePath "C:\CKLS\Merged.cklb" -IncludeNR
#>
function Merge-StigCKLBFiles {
    Param
    (
        [Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_ -and $_ -like "*.cklb"})][string]$DestinationCKLBFile,
        [Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_ -and $_ -like "*.cklb"})][string]$SourceCKLBFile,
        [Parameter(Mandatory=$true)][string]$SaveFilePath,
        [switch]$IncludeNR,
        [switch]$DontCopyHostInfo,
        [switch]$DontOverwriteVulns
    )
    #Load both inputs
    $DestinationCKLB = Import-StigCKLBFile -Path $DestinationCKLBFile
    $SourceCKLB = Import-StigCKLBFile -Path $SourceCKLBFile
    #Merge 'em
    Merge-StigCKLBData -SourceCKLB $SourceCKLB -DestinationCKLB $DestinationCKLB -IncludeNR:$IncludeNR -DontCopyHostInfo:$DontCopyHostInfo -DontOverwriteVulns:$DontOverwriteVulns
    #Save output
    Export-StigCKLBFile -CKLBData $DestinationCKLB -Path $SaveFilePath
}

#endregion

#Export members
Export-ModuleMember -Function Import-StigCKLBFile, Export-StigCKLBFile, Set-StigCKLBTargetData, Get-StigCKLBTargetData, 
                              Get-StigCKLBStigAttribute, Get-StigCKLBStigInfo, Get-StigCKLBVulnIDs, Get-StigCKLBRuleIDs, 
                              Get-StigCKLBRuleInfo, Set-StigCKLBRuleFinding, Set-StigCKLBRuleStatusFromRegistry, Get-StigCKLBMetrics,
                              Merge-StigCKLBData, Merge-StigCKLBFiles
