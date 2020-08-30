# IIS_8-5_Site_STIG

This check built for:
- Microsoft IIS 8.5 Site STIG
- Version 1, Release: 11 Benchmark Date: 24 Jul 2020

## Usage

Run Start-STIGCheck.ps1 with your IIS 10 Site CKL against a target. Example

```powershell
&"C:\StigSupportModule\Checks\Start-STIGCheck.ps1" -MachineName MyRemoteComputer -CKL "C:\BlankCKLs\BlankIIS8.ckl" -CheckDirectory "C:\StigSupportModule\Checks" -SavePath "C:\FilledCKLs\MyFilledCKL.ckl" -InitObject "Default Web Site" -Verbose
```