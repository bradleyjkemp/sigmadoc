---
title: "Code Execution via Pcwutl.dll"
aliases:
  - "/rule/9386d78a-7207-4048-9c9f-a93a7c2d1c05"


tags:
  - attack.defense_evasion
  - attack.t1218.011



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.

<!--more-->


## Known false-positives

* Use of Program Compatibility Troubleshooter Helper



## References

* https://github.com/api0cradle/LOLBAS/blob/master/OSLibraries/Pcwutl.md
* https://twitter.com/harr0ey/status/989617817849876488


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_pcwutl.yml))
```yaml
title: Code Execution via Pcwutl.dll
id: 9386d78a-7207-4048-9c9f-a93a7c2d1c05
status: test
description: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
author: Julia Fomina, oscd.community
references:
  - https://github.com/api0cradle/LOLBAS/blob/master/OSLibraries/Pcwutl.md
  - https://twitter.com/harr0ey/status/989617817849876488
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'pcwutl'
      - 'LaunchApplication'
  condition: selection
falsepositives:
  - Use of Program Compatibility Troubleshooter Helper
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218.011

```
