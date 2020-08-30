# StigSupport.psm1

This is the core module for this entire project. It provides the necessary functions to read and write CKL files. This module can assist in automating checks, running metrics on CKL files and merging checks from different CKL files into one. 

## Commands

A brief overview of the commands in this module is below. More detailed information with examples are located in the module itself.

### Convert-ManualXCCDFToCKL

Will convert a manual xccdf to a blank checklist

```powershell
Convert-ManualXCCDFToCKL [-XCCDFPath] <String> [[-SaveLocation] <Object>] [<CommonParameters>]
```

### Export-StigCKL

Saves a loaded CKL file to disk

```powershell
Export-StigCKL [-CKLData] <XmlDocument> [-Path] <String> [-AddHostData] [<CommonParameters>]
```

### Get-CCIReferences

Gets the references for the specified CCI ID (Generally IA Control Policies)

```powershell
Get-CCIReferences [-CCIData] <XmlDocument> [-CCIID] <String> [<CommonParameters>]
```

### Get-CCIVulnReferences

Gets the references for the specified CCI IDs associated with the specified VulnID

```powershell
Get-CCIVulnReferences [-CCIData] <XmlDocument> [-CKLData] <XmlDocument> [[-VulnID] <Object>] [[-RuleID] <Object>]
[<CommonParameters>]
```

### Get-CheckListInfo

Gets general info from the checklist (Release, Title, Description)

```powershell
Get-CheckListInfo [-CKLData] <XmlDocument> [<CommonParameters>]
```

### Get-CKLHostData

Gets the host information from the CKLData

```powershell
Get-CKLHostData [-CKLData] <XmlDocument> [<CommonParameters>]
```

### Get-CKLVulnInformation

Returns an array of the vulns in the CKL file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

```powershell
Get-CKLVulnInformation [-CKLData] <XmlDocument> [<CommonParameters>]
```

### Get-StigInfoAttribute

Gets a stig info attribute

```powershell
Get-StigInfoAttribute [-CKLData] <xml> [-Attribute] <Object> [<CommonParameters>]
```

### Get-StigMetrics

Returns a complex object of metrics on the statuses of the checks in a directory of checklists, or a checklist

```powershell
Get-StigMetrics [[-Path] <Object>] [<CommonParameters>]
```

### Get-VulnCheckResult

Gets the status of a single vuln check, or an array of the status of all vuln checks in a CKL

```powershell
Get-VulnCheckResult [-CKLData] <XmlDocument> [[-VulnID] <Object>] [[-RuleID] <Object>] [<CommonParameters>]
```

### Get-VulnFindingAttribute

Gets a vuln's finding attribute (Status, Comments, Details, etc)

```powershell
Get-VulnFindingAttribute [-CKLData] <XmlDocument> [[-VulnID] <Object>] [[-RuleID] <Object>] [-Attribute] <Object>
[<CommonParameters>]
```

### Get-VulnIDs

Returns all VulnIDs contained in the CKL

```powershell
Get-VulnIDs [-CKLData] <XmlDocument> [<CommonParameters>]
```

### Get-VulnInfoAttribute

Gets a vuln's informational attribute

```powershell
Get-VulnInfoAttribute [-CKLData] <XmlDocument> [[-VulnID] <Object>] [[-RuleID] <Object>] [-Attribute] <Object>
[<CommonParameters>]
```

### Get-VulnInformation

Returns an array of the vulns in the CKL file and all it's associated informational properties (Vuln_ID, Rule_ID, CCI_REF etc)

```powershell
Get-VulnInformation [-CKLData] <XmlDocument> [-NoAliases] [<CommonParameters>]
```

### Get-XCCDFHostData

Gets host info from XCCDF

```powershell
Get-XCCDFHostData [-XCCDF] <XmlDocument> [<CommonParameters>]
```

### Get-XCCDFInfo

Gets general info from the XCCDF (Release, Title, Description)

```powershell
Get-XCCDFInfo [-XCCDF] <XmlDocument> [<CommonParameters>]
```

### Get-XCCDFResults

Returns stig results from an XCCDF file

```powershell
Get-XCCDFResults [-XCCDF] <XmlDocument> [<CommonParameters>]
```

### Get-XCCDFVulnInformation

Returns an array of the vulns in the xccdf file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)

```powershell
Get-XCCDFVulnInformation [-XCCDF] <XmlDocument> [-Full] [<CommonParameters>]
```

### Import-CCIList

Imports the CCIList XML from DISA

```powershell
Import-CCIList [-Path] <string> [<CommonParameters>]
```

### Import-StigCKL

Load a CKL file as an [XML] element. This can then be passed to other functions in this module.

```powershell
Import-StigCKL [-Path] <String> [<CommonParameters>]
```

### Import-XCCDF

Load an XCCDF file into a [xml]

```powershell
Import-XCCDF [-Path] <string> [<CommonParameters>]
```

### Merge-CKLData

Merges two loaded CKLs

```powershell
Merge-CKLData [-SourceCKL] <XmlDocument> [-DestinationCKL] <XmlDocument> [-IncludeNR] [-DontCopyHostInfo]
[-DontOverwriteVulns] [<CommonParameters>]
```

### Merge-CKLs

Merges two CKL files and saves it as a new CKL. Largely a wrapper around Merge-CKLData.

```powershell
Merge-CKLs [-DestinationCKLFile] <String> [-SourceCKLFile] <String> [-SaveFilePath] <String> [-IncludeNR]
[-DontCopyHostInfo] [-DontOverwriteVulns] [<CommonParameters>]
```

### Merge-XCCDFHostDataToCKL

Adds XCCDF host info into a loaded CKL data

```powershell
Merge-XCCDFHostDataToCKL [-CKLData] <XmlDocument> [-XCCDF] <XmlDocument> [<CommonParameters>]
```

### Merge-XCCDFToCKL

Adds XCCDF results into a loaded CKL data

```powershell
Merge-XCCDFToCKL [-CKLData] <XmlDocument> [-XCCDF] <XmlDocument> [-NoCommentsOnOpen] [<CommonParameters>]
```

### Repair-StigCKL

Opens and re-saves a CKL, may fix formatting issues

```powershell
Repair-StigCKL [-Path] <String> [<CommonParameters>]
```

### Set-CKLHostData

Sets host data in CKL. If any parameters are blank, they will be set to running machine

```powershell
Set-CKLHostData [-CKLData] <XmlDocument> [[-Host] <Object>] [[-FQDN] <Object>] [[-Mac] <Object>] [[-IP] <Object>]
[[-Role] <Object>] [-AutoFill] [<CommonParameters>]
```

### Set-VulnCheckResult

Sets the findings information for a single vuln

```powershell
Set-VulnCheckResult [-CKLData] <XmlDocument> [[-VulnID] <Object>] [[-RuleID] <Object>] [[-Details] <Object>]
[[-Comments] <Object>] [-Result] <Object> [<CommonParameters>]
```

### Set-VulnCheckResultFromRegistry

Sets a vuln status based on a registry check

```powershell
Set-VulnCheckResultFromRegistry [-VulnID] <String> [-RegKeyPath] <String> [-RequiredKey] <String> [-RequiredValue]
<Object> [-CKLData] <XmlDocument> [[-Comments] <String>] [<CommonParameters>]
```

### Set-VulnFindingAttribute

Sets a vuln's finding attribute (Status, Comments, Details, etc)

```powershell
Set-VulnFindingAttribute [-CKLData] <XmlDocument> [[-VulnID] <Object>] [[-RuleID] <Object>] [-Attribute] <Object>
[-Value] <String> [<CommonParameters>]
```