---
title: "DLL Injection with Tracker.exe"
aliases:
  - "/rule/148431ce-4b70-403d-8525-fcc2993f29ea"


tags:
  - attack.defense_evasion
  - attack.t1055.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This rule detects DLL injection and execution via LOLBAS - Tracker.exe

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Tracker.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_tracker_execution.yml))
```yaml
title: DLL Injection with Tracker.exe
id: 148431ce-4b70-403d-8525-fcc2993f29ea
status: test
description: This rule detects DLL injection and execution via LOLBAS - Tracker.exe
author: 'Avneet Singh @v3t0_, oscd.community'
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Tracker.yml
date: 2020/10/18
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  process_name:
    Image|endswith:
      - '\tracker.exe'
  process_description:
    Description:
      - 'Tracker'
  commandline_param1:
    CommandLine|contains:
      - ' /d '
  commandline_param2:
    CommandLine|contains:
      - ' /c '
  condition: (process_name or process_description) and commandline_param1 and commandline_param2
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1055.001

```
