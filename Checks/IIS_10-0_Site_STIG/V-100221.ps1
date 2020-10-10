Param($BeginData)
Write-Verbose "V-100221"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$IsEnabled = (Get-WebConfigurationProperty "system.webServer/security/authentication/anonymousAuthentication" -name enabled -PSPath "IIS:\Sites\$($BeginData.Site)").Value
$UserName = (Get-WebConfigurationProperty "system.webServer/security/authentication/anonymousAuthentication" -name userName -PSPath "IIS:\Sites\$($BeginData.Site)").Value
$RestrictedGroups = @("Administrators",
"Backup Operators",
"Certificate Services",
"Distributed COM Users",
"Event Log Readers",
"Network Configuration Operators",
"Performance Log Users",
"Performance Monitor Users",
"Power Users",
"Print Operators",
"Remote Desktop Users",
"Replicator")

function Get-LocalGroupsRecurse {
    Param($UserName)
    [ADSI]$S = "WinNT://localhost"
    $Memberships = $S.children.where({$_.class -eq 'group'}) |
        Select @{Name="Computername";Expression={$_.Parent.split("/")[-1] }},
        @{Name="Name";Expression={$_.name.value}},
        @{Name="Members";Expression={
        [ADSI]$group = "$($_.Parent)/$($_.Name),group"
        $members = $Group.psbase.Invoke("Members")
        ($members | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        })
    }}
    $Memberships = $Memberships | Where-Object {$_.Members -ne $null -and $_.Members.Length -gt 0}
    $Groups=@()
    $GroupsToCheck=@($UserName)
    for ($I=0; $I -ne $GroupsToCheck.Length; $I++) {
        #Loop through all groups
        foreach($Membership in $Memberships) {
            #Check if the group contains the object we are looking for
            if ($Membership.Members.Contains($GroupsToCheck[$I])) {
                #If it does, check if we already have it in our return object
                if (-not $Groups.Contains($Membership.Name)) {
                    #If not add it
                    $Groups+=$Membership.Name
                    #And add it to be checked
                    if (-not $GroupsToCheck.Contains($Membership.Name)) {
                        $GroupsToCheck+=$Membership.Name
                    }
                }
            }
        }
    }
    return $Groups
}

if ($IsEnabled -ne $null)
{
    $Details+="Anonymous access enabled: "+$IsEnabled.ToString()+"`r`n"
    if ($UserName -eq "")
    {
        $Details+="Account in use is `"AppPool`"`r`n"
    } else {
        $Details+="Account in use is `""+$UserName+"`"`r`n"
        #Check if the username is in the restircted local groups
    }
    if ($IsEnabled) {
        if ($UserName -eq "IUSR") {
            #Handle group check
            $GroupMembership = Get-LocalGroupsRecurse -UserName $UserName
            if ($GroupMembership.Length -gt 0) {
                foreach($G in $GroupMembership) {
                    $Comments+="Member of $G`r`n"
                }
                foreach($RG in $RestrictedGroups) {
                    if ($GroupMembership.Contains($RG)) {
                        $Result="Open"
                        $Details+="$UserName is a member of $RG`r`n"
                        break;
                    }
                }
                if ($Result -ne "Open") {
                    $Result="NotAFinding"
                    $Details+="$UserName does not appear to be part of any restricted groups`r`n"
                }
            } else {
                $Result="NotAFinding"
                $Details+="$UserName does not appear to be part of any groups`r`n"
            }
        } else {
            $Result="Not_Reviewed"
            $Details += "Please check sensitive groups for the above username`r`n"
        }
    } else {
        $Result="NotAFinding"
        $Details+="Anonymous access not enabled`r`n"
    }
    #TODO: Maybe make this more automated, but it is a big check
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}
