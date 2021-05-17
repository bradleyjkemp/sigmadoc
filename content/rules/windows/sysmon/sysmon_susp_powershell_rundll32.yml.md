---
title: "PowerShell Rundll32 Remote Thread Creation"
aliases:
  - "/rule/99b97608-3e21-4bfe-8217-2a127c396a0e"

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1085
  - attack.t1218.011
  - attack.t1086
  - attack.t1059.001



status: experimental



level: high



date: Mon, 25 Jun 2018 15:23:19 +0200


---

Detects PowerShell remote thread creation in Rundll32.exe

<!--more-->


## Known false-positives

* Unkown



## References

* https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html


## Raw rule
```yaml
title: PowerShell Rundll32 Remote Thread Creation
id: 99b97608-3e21-4bfe-8217-2a127c396a0e
status: experimental
description: Detects PowerShell remote thread creation in Rundll32.exe
author: Florian Roth
references:
    - https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html
date: 2018/06/25
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage: '*\powershell.exe'
        TargetImage: '*\rundll32.exe'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085          # an old one
    - attack.t1218.011
    - attack.t1086          # an old one
    - attack.t1059.001
falsepositives:
    - Unkown
level: high

```
