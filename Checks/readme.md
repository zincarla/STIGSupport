# Checks

This section contains scripts to help automate certain checks. Keep in mind there may be bugs and that you should verify all code before use and check results.

## Usage

Run Start-STIGCheck.ps1 with your specific CKL against a target. Example

```powershell
&"C:\StigSupportModule\Checks\Start-STIGCheck.ps1" -MachineName MyRemoteComputer -CKL "C:\BlankCKLs\BlankMSDotNet.ckl" -CheckDirectory "C:\StigSupportModule\Checks" -SavePath "C:\FilledCKLs\MyFilledCKL.ckl" -Verbose
```

The script will detect which check scripts to run based on the STIG ID in the CKL. It will run the checks and fill out the provided CKL and save it to SavePath. Sometimes a check may require you to pass more specific information in the InitObject parameter, see the readme file of each STIG check folder for more information.

## Structure/Development

- Each STIG should be placed in it's own folder with a README.MD specifying which STIG and version the checks are built for. The folder should be named based on the STIG ID.
- A begin.ps1 can be used to cache information required for sub-checks. For example, this is used in the .Net check to cache all *.exe.config file locations so we do not have to rescan the drive for the files with each check.
- If this returns an object with a property of "IsApplicable" and it is set to false, then the rest of the checks will be skipped. The return object from this script will be passed to all subcheck scripts.
- An initobject can be passed using Start-STIGCheck, this is passed directly to begin.ps1 and can further be passed if added to begin.ps1's return object.
- An end.ps1 can be used to release resources. This is optional.
- Each vuln should be placed into it's own ps1 file with the vuln id as the name. (Ex. V-1888.ps1)
- The vuln script should return an object or hashtable with properties for Comments, Details, and Result with result being either Open, Not_Reviewed, Not_Applicable or NotAFinding. Any additional properties are ignored. Invalid results are converted to Not_Reviewed.
- A blank check template is included.
