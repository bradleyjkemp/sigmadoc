---
title: "Winword.exe Loads Suspicious DLL"
aliases:
  - "/rule/2621b3a6-3840-4810-ac14-a02426086171"


tags:
  - attack.defense_evasion
  - attack.t1202



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Winword.exe loading of custmom dll via /l cmd switch

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OtherMSBinaries/Winword.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_winword_dll_load.yml))
```yaml
title: Winword.exe Loads Suspicious DLL
id: 2621b3a6-3840-4810-ac14-a02426086171
status: test
description: Detects Winword.exe loading of custmom dll via /l cmd switch
author: Victor Sergeev, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OtherMSBinaries/Winword.yml
date: 2020/10/09
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  image_path:
    Image|endswith: '\winword.exe'
  cmd:
    CommandLine|contains: '/l'
  condition: image_path and cmd
fields:
  - CommandLine
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1202

```
