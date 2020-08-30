Write-Verbose "V-100173"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "URIEnableCache"  -ErrorAction SilentlyContinue) {
    $URIEnableCache = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "URIEnableCache"
}
if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "URIEnableCache"  -ErrorAction SilentlyContinue) {
    $UriMaxUriBytes = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "UriMaxUriBytes"
}
if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "URIEnableCache"  -ErrorAction SilentlyContinue) {
    $UriScavengerPeriod = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "UriScavengerPeriod"
}

if ($URIEnableCache -eq $null) {
    $Result="Open"
    $Details += "URIEnableCache is not set `r`n"
} else {
    $Comments += "URIEnableCache = $URIEnableCache `r`n"
}
if ($UriMaxUriBytes -eq $null) {
    $Result="Open"
    $Details += "UriMaxUriBytes is not set `r`n"
} else {
    $Comments += "UriMaxUriBytes = $UriMaxUriBytes `r`n"
}
if ($UriScavengerPeriod -eq $null) {
    $Result="Open"
    $Details += "UriScavengerPeriod is not set `r`n"
} else {
    $Comments += "UriScavengerPeriod = $UriScavengerPeriod `r`n"
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}