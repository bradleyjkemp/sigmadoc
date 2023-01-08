---
title: "Live Memory Dump Using Powershell"
aliases:
  - "/rule/cd185561-4760-45d6-a63e-a51325112cae"
ruleid: cd185561-4760-45d6-a63e-a51325112cae

tags:
  - attack.t1003



status: experimental





date: Tue, 21 Sep 2021 14:55:50 +0200


---

Detects usage of a PowerShell command to dump the live memory of a Windows machine

<!--more-->


## Known false-positives

* Diagnostics



## References

* https://docs.microsoft.com/en-us/powershell/module/storage/get-storagediagnosticinfo


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_memorydump_getstoragediagnosticinfo.yml))
```yaml
title: Live Memory Dump Using Powershell
id: cd185561-4760-45d6-a63e-a51325112cae
status: experimental
description: Detects usage of a PowerShell command to dump the live memory of a Windows machine
date: 2021/09/21
modified: 2021/10/16
references:
    - https://docs.microsoft.com/en-us/powershell/module/storage/get-storagediagnosticinfo
tags:
    - attack.t1003
author: Max Altgelt
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    dump:
        ScriptBlockText|contains|all:
            - 'Get-StorageDiagnosticInfo'
            - '-IncludeLiveDump'
    condition: dump
falsepositives:
    - Diagnostics
level: high

```
