---
title: "DHCP Server Error Failed Loading the CallOut DLL"
aliases:
  - "/rule/75edd3fd-7146-48e5-9848-3013d7f0282c"

tags:
  - attack.defense_evasion
  - attack.t1073
  - attack.t1574.002



date: Mon, 15 May 2017 20:58:31 +0200


---

This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded

<!--more-->


## Known false-positives

* Unknown



## References

* https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
* https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
* https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx


## Raw rule
```yaml
title: DHCP Server Error Failed Loading the CallOut DLL
id: 75edd3fd-7146-48e5-9848-3013d7f0282c
description: This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded
status: experimental
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
modified: 2019/07/17
tags:
    - attack.defense_evasion
    - attack.t1073           # an old one
    - attack.t1574.002
author: "Dimitrios Slamaris, @atc_project (fix)"
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 1031
            - 1032
            - 1034
        Source: Microsoft-Windows-DHCP-Server
    condition: selection
falsepositives:
    - Unknown
level: critical

```