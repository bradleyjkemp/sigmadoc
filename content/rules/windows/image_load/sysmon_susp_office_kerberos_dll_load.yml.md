---
title: "Active Directory Kerberos DLL Loaded Via Office Applications"
aliases:
  - "/rule/7417e29e-c2e7-4cf6-a2e8-767228c64837"

tags:
  - attack.execution
  - attack.t1204
  - attack.t1204.002



date: Wed, 19 Feb 2020 10:13:44 -0500


---

Detects Kerberos DLL being loaded by an Office Product

<!--more-->


## Known false-positives

* Alerts on legitimate macro usage as well, will need to filter as appropriate



## References

* https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16


## Raw rule
```yaml
title: Active Directory Kerberos DLL Loaded Via Office Applications
id: 7417e29e-c2e7-4cf6-a2e8-767228c64837
status: experimental
description: Detects Kerberos DLL being loaded by an Office Product
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020/02/19
modified: 2020/08/23
tags:
    - attack.execution
    - attack.t1204          # an old one
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image:
            - '*\winword.exe'
            - '*\powerpnt.exe'
            - '*\excel.exe'
            - '*\outlook.exe'
        ImageLoaded:
            - '*\kerberos.dll'
    condition: selection
falsepositives:
    - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: high

```
