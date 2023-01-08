---
title: "Suspicious Runscripthelper.exe"
aliases:
  - "/rule/eca49c87-8a75-4f13-9c73-a5a29e845f03"
ruleid: eca49c87-8a75-4f13-9c73-a5a29e845f03

tags:
  - attack.execution
  - attack.t1059
  - attack.defense_evasion
  - attack.t1202



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects execution of powershell scripts via Runscripthelper.exe

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Runscripthelper.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_runscripthelper.yml))
```yaml
title: Suspicious Runscripthelper.exe
id: eca49c87-8a75-4f13-9c73-a5a29e845f03
status: test
description: Detects execution of powershell scripts via Runscripthelper.exe
author: Victor Sergeev, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Runscripthelper.yml
date: 2020/10/09
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  image_path:
    Image|endswith: '\Runscripthelper.exe'
  cmd:
    CommandLine|contains: 'surfacecheck'
  condition: image_path and cmd
fields:
  - CommandLine
falsepositives:
  - Unknown
level: medium
tags:
  - attack.execution
  - attack.t1059
  - attack.defense_evasion
  - attack.t1202

```
