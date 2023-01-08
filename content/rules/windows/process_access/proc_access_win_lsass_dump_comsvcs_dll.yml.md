---
title: "Lsass Memory Dump via Comsvcs DLL"
aliases:
  - "/rule/a49fa4d5-11db-418c-8473-1e014a8dd462"
ruleid: a49fa4d5-11db-418c-8473-1e014a8dd462

tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/shantanukhande/status/1229348874298388484
* https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml))
```yaml
title: Lsass Memory Dump via Comsvcs DLL
id: a49fa4d5-11db-418c-8473-1e014a8dd462
description: Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.
status: experimental
date: 2020/10/20
modified: 2021/06/21
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.credential_access
    - attack.t1003.001
references:
    - https://twitter.com/shantanukhande/status/1229348874298388484
    - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage: 'C:\Windows\System32\rundll32.exe'
        CallTrace|contains: 'comsvcs.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
