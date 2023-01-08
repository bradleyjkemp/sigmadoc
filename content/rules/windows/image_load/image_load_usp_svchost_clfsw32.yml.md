---
title: "APT PRIVATELOG Image Load Pattern"
aliases:
  - "/rule/33a2d1dd-f3b0-40bd-8baf-7974468927cc"
ruleid: 33a2d1dd-f3b0-40bd-8baf-7974468927cc

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1055



status: experimental





date: Tue, 7 Sep 2021 10:10:14 +0200


---

Detects an image load pattern as seen when a tool named PRIVATELOG is used and rarely observed under legitimate circumstances

<!--more-->


## Known false-positives

* Rarely observed



## References

* https://www.fireeye.com/blog/threat-research/2021/09/unknown-actor-using-clfs-log-files-for-stealth.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_usp_svchost_clfsw32.yml))
```yaml
title: APT PRIVATELOG Image Load Pattern
id: 33a2d1dd-f3b0-40bd-8baf-7974468927cc
status: experimental
description: Detects an image load pattern as seen when a tool named PRIVATELOG is used and rarely observed under legitimate circumstances
references:
    - https://www.fireeye.com/blog/threat-research/2021/09/unknown-actor-using-clfs-log-files-for-stealth.html
author: Florian Roth
date: 2021/09/07
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        ImageLoaded|endswith: '\clfsw32.dll'
    condition: selection
falsepositives:
    - Rarely observed
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
```
