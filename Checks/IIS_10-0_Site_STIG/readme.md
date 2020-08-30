# IIS_10-0_Site_STIG

This check built for:
- Microsoft IIS 10.0 Site STIG
- Version 1, Release: 2 Benchmark Date: 24 Jul 2020

## Usage

Run Start-STIGCheck.ps1 with your IIS 10 Site CKL against a target. Example

```powershell
&"C:\StigSupportModule\Checks\Start-STIGCheck.ps1" -MachineName MyRemoteComputer -CKL "C:\BlankCKLs\BlankIIS10.ckl" -CheckDirectory "C:\StigSupportModule\Checks" -SavePath "C:\FilledCKLs\MyFilledCKL.ckl" -InitObject "Default Web Site" -Verbose
```