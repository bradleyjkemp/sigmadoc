---
title: "Alternate PowerShell Hosts"
aliases:
  - "/rule/64e8e417-c19a-475a-8d19-98ea705394cc"


tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe

<!--more-->


## Known false-positives

* Programs using PowerShell directly without invocation of a dedicated interpreter
* MSP Detection Searcher
* Citrix ConfigSync.ps1



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190815181010.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_module/posh_pm_alternate_powershell_hosts.yml))
```yaml
title: Alternate PowerShell Hosts
id: 64e8e417-c19a-475a-8d19-98ea705394cc
description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
status: test
date: 2019/08/11
modified: 2022/02/16
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190815181010.html
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_module
    definition: PowerShell Module Logging must be enabled
detection:
    selection:
        ContextInfo: '*'
    filter:
        ContextInfo|contains: 'powershell.exe' # Host Application=...powershell.exe or Application hote=...powershell.exe in French Win10 event
    filter_citrix:
        ContextInfo|contains: 'ConfigSyncRun.exe'
    condition: selection and not 1 of filter*
falsepositives:
    - Programs using PowerShell directly without invocation of a dedicated interpreter
    - MSP Detection Searcher
    - Citrix ConfigSync.ps1
level: medium 
```
