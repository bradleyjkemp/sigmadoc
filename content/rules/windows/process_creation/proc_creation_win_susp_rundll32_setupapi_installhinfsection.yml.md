---
title: "Suspicious Rundll32 Setupapi.dll Activity"
aliases:
  - "/rule/285b85b1-a555-4095-8652-a8a4106af63f"


tags:
  - attack.defense_evasion
  - attack.t1218.011



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

setupapi.dll library provide InstallHinfSection function for processing INF files. INF file may contain instructions allowing to create values in the registry, modify files and install drivers. This technique could be used to obtain persistence via modifying one of Run or RunOnce registry keys, run process or use other DLLs chain calls (see references) InstallHinfSection function in setupapi.dll calls runonce.exe executable regardless of actual content of INF file.

<!--more-->


## Known false-positives

* Scripts and administrative tools that use INF files for driver installation with setupapi.dll



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Setupapi.yml
* https://gist.githubusercontent.com/bohops/0cc6586f205f3691e04a1ebf1806aabd/raw/baf7b29891bb91e76198e30889fbf7d6642e8974/calc_exe.inf
* https://raw.githubusercontent.com/huntresslabs/evading-autoruns/master/shady.inf
* https://twitter.com/Z3Jpa29z/status/1313742350292746241?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_setupapi_installhinfsection.yml))
```yaml
title: Suspicious Rundll32 Setupapi.dll Activity
id: 285b85b1-a555-4095-8652-a8a4106af63f
status: test
description: setupapi.dll library provide InstallHinfSection function for processing INF files. INF file may contain instructions allowing to create values in the registry, modify files and install drivers. This technique could be used to obtain persistence via modifying one of Run or RunOnce registry keys, run process or use other DLLs chain calls (see references) InstallHinfSection function in setupapi.dll calls runonce.exe executable regardless of actual content of INF file.
author: Konstantin Grishchenko, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Setupapi.yml
  - https://gist.githubusercontent.com/bohops/0cc6586f205f3691e04a1ebf1806aabd/raw/baf7b29891bb91e76198e30889fbf7d6642e8974/calc_exe.inf
  - https://raw.githubusercontent.com/huntresslabs/evading-autoruns/master/shady.inf
  - https://twitter.com/Z3Jpa29z/status/1313742350292746241?s=20
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\runonce.exe'
    ParentImage|endswith: '\rundll32.exe'
    ParentCommandLine|contains|all:
      - 'setupapi.dll'
      - 'InstallHinfSection'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Scripts and administrative tools that use INF files for driver installation with setupapi.dll
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218.011

```