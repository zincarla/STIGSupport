Write-Verbose "V-7055"
$Children = @()
$Children += Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\StrongName\Verification\" -ErrorAction SilentlyContinue
$Children += Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\StrongName\Verification\" -ErrorAction SilentlyContinue
if ($Children.Length -gt 0)
{
    $ToWrite = "Keys found"
    foreach ($Child in $Children)
    {
        $ToWrite+="`r`n"+$Child.Name
    }
    return @{Details=$ToWrite;
            Comments=$Comments;
            Result="NotReviewed"}
}
else
{
    return @{Details="No keys found under HKLM:\SOFTWARE\Microsoft\StrongName\Verification\ or HKLM:\SOFTWARE\Wow6432Node\Microsoft\StrongName\Verification\";
            Comments=$Comments;
            Result="NotAFinding"}
}