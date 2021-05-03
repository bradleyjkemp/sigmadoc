---
title: "Successful Overpass the Hash Attempt"
aliases:
  - "/rule/192a0330-c20b-4356-90b6-7b7049ae0b87"

tags:
  - attack.lateral_movement
  - attack.t1075
  - attack.s0002
  - attack.t1550.002



date: Mon, 12 Feb 2018 21:57:22 +0100


---

Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.

<!--more-->


## Known false-positives

* Runas command-line tool using /netonly parameter



## References

* https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html


## Raw rule
```yaml
title: Successful Overpass the Hash Attempt
id: 192a0330-c20b-4356-90b6-7b7049ae0b87
status: experimental
description: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
references:
    - https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html
author: Roberto Rodriguez (source), Dominik Schaudel (rule)
date: 2018/02/12
tags:
    - attack.lateral_movement
    - attack.t1075          # an old one
    - attack.s0002
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: seclogo
        AuthenticationPackageName: Negotiate
    condition: selection
falsepositives:
    - Runas command-line tool using /netonly parameter
level: high

```