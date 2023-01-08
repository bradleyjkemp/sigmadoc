---
title: "Suspicious Interactive PowerShell as SYSTEM"
aliases:
  - "/rule/5b40a734-99b6-4b98-a1d0-1cea51a08ab2"
ruleid: 5b40a734-99b6-4b98-a1d0-1cea51a08ab2



status: experimental





date: Tue, 7 Dec 2021 07:03:48 +0100


---

Detects the creation of files that indicator an interactive use of PowerShell in the SYSTEM user context

<!--more-->


## Known false-positives

* Administrative activity
* PowerShell scripts running as SYSTEM user



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PowerSploit_Invoke-Mimikatz.htm


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_system_interactive_powershell.yml))
```yaml
title: Suspicious Interactive PowerShell as SYSTEM
id: 5b40a734-99b6-4b98-a1d0-1cea51a08ab2
status: experimental
description: Detects the creation of files that indicator an interactive use of PowerShell in the SYSTEM user context
author: Florian Roth
references:
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PowerSploit_Invoke-Mimikatz.htm
date: 2021/12/07
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename: 
    - 'C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    - 'C:\Windows\System32\config\systemprofile\AppData\\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive'
  condition: selection
falsepositives:
  - Administrative activity
  - PowerShell scripts running as SYSTEM user
level: high

```
