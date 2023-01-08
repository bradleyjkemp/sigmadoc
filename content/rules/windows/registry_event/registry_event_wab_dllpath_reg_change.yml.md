---
title: "Execution DLL of Choice Using WAB.EXE"
aliases:
  - "/rule/fc014922-5def-4da9-a0fc-28c973f41bfb"
ruleid: fc014922-5def-4da9-a0fc-28c973f41bfb

tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This rule detects that the path to the DLL written in the registry is different from the default one. Launched WAB.exe tries to load the DLL from Registry.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Wab.yml
* https://twitter.com/Hexacorn/status/991447379864932352
* http://www.hexacorn.com/blog/2018/05/01/wab-exe-as-a-lolbin/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_wab_dllpath_reg_change.yml))
```yaml
title: Execution DLL of Choice Using WAB.EXE
id: fc014922-5def-4da9-a0fc-28c973f41bfb
description: This rule detects that the path to the DLL written in the registry is different from the default one. Launched WAB.exe tries to load the DLL from Registry.
status: experimental
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Wab.yml
    - https://twitter.com/Hexacorn/status/991447379864932352
    - http://www.hexacorn.com/blog/2018/05/01/wab-exe-as-a-lolbin/
tags:
    - attack.defense_evasion
    - attack.t1218
date: 2020/10/13
modified: 2022/01/13
author: oscd.community, Natalia Shornikova
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue 
        TargetObject|endswith: '\Software\Microsoft\WAB\DLLPath'
    filter:
        Details: '%CommonProgramFiles%\System\wab32.dll'
    condition: selection and not filter
falsepositives: 
 - Unknown
level: high

```
