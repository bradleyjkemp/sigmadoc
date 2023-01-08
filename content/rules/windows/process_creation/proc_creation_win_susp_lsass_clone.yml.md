---
title: "Suspicious LSASS Process Clone"
aliases:
  - "/rule/c8da0dfd-4ed0-4b68-962d-13c9c884384e"
ruleid: c8da0dfd-4ed0-4b68-962d-13c9c884384e

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001



status: experimental





date: Sat, 27 Nov 2021 13:32:41 +0100


---

Detects a suspicious LSASS process process clone that could be a sign of process dumping activity

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
* https://twitter.com/Hexacorn/status/1420053502554951689
* https://twitter.com/SBousseaden/status/1464566846594691073?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_lsass_clone.yml))
```yaml
title: Suspicious LSASS Process Clone
id: c8da0dfd-4ed0-4b68-962d-13c9c884384e
status: experimental
description: Detects a suspicious LSASS process process clone that could be a sign of process dumping activity
references:
    - https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
    - https://twitter.com/Hexacorn/status/1420053502554951689
    - https://twitter.com/SBousseaden/status/1464566846594691073?s=20
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.001
author: Florian Roth, Samir Bousseaden
date: 2021/11/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Windows\System32\lsass.exe'
        ParentImage|endswith: '\Windows\System32\lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
