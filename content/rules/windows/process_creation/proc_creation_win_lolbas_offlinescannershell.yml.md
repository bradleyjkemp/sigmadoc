---
title: "Suspicious OfflineScannerShell.exe Execution From Another Folder"
aliases:
  - "/rule/02b18447-ea83-4b1b-8805-714a8a34546a"
ruleid: 02b18447-ea83-4b1b-8805-714a8a34546a

tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Sun, 6 Mar 2022 12:10:51 +0100


---

Use OfflineScannerShell.exe to execute mpclient.dll library in the current working directory

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/OfflineScannerShell/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_offlinescannershell.yml))
```yaml
title: Suspicious OfflineScannerShell.exe Execution From Another Folder
id: 02b18447-ea83-4b1b-8805-714a8a34546a
status: experimental
description: Use OfflineScannerShell.exe to execute mpclient.dll library in the current working directory 
references:
    - https://lolbas-project.github.io/lolbas/Binaries/OfflineScannerShell/
author: frack113
date: 2022/03/06
logsource:
    category: process_creation
    product: windows
detection:
    lolbas:
        Image|endswith: '\OfflineScannerShell.exe'
    filter_correct:
        CurrentDirectory: 'C:\Program Files\Windows Defender\Offline\'
    filter_missing: 
        CurrentDirectory: null
    condition: lolbas and not 1 of filter_*
falsepositives:
    - unknown
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218 

```
