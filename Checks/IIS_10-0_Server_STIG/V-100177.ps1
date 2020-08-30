Write-Verbose "V-100177"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

$Requirements = @(
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server";Name="DisabledByDefault";Value=0},

    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server";Name="DisabledByDefault";Value=1}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server";Name="DisabledByDefault";Value=1}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server";Name="DisabledByDefault";Value=1}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server";Name="DisabledByDefault";Value=1}

    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server";Name="Enabled";Value=0}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server";Name="Enabled";Value=0}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server";Name="Enabled";Value=0}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server";Name="Enabled";Value=0}
)

foreach ($Requirement in $Requirements) {
    if (Get-ItemProperty -Path $Requirement.Key -Name $Requirement.Name -ErrorAction SilentlyContinue) {
        $ValueToCheck = Get-ItemPropertyValue -Path $Requirement.Key -Name $Requirement.Name
        if ($ValueToCheck -ne $Requirement.Value) {
            $Result = "Open"
            $Details += "$($Requirement.Key) : $($Requirement.Name), is '$ValueToCheck' instead of '$($Requirement.Value)'.`r`n"
        } else {
            $Comments += "$($Requirement.Key) : $($Requirement.Name), is '$ValueToCheck'.`r`n"            
        }
    } else {
        $Result = "Open"
        $Details += "$($Requirement.Key) : $($Requirement.Name), is missing.`r`n"
    }
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}