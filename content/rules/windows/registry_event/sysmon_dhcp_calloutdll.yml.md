---
title: "DHCP Callout DLL Installation"
aliases:
  - "/rule/9d3436ef-9476-4c43-acca-90ce06bdf33a"

tags:
  - attack.defense_evasion
  - attack.t1073
  - attack.t1574.002
  - attack.t1112



date: Mon, 15 May 2017 20:58:31 +0200


---

Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)

<!--more-->


## Known false-positives

* unknown



## References

* https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
* https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
* https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx


## Raw rule
```yaml
title: DHCP Callout DLL Installation
id: 9d3436ef-9476-4c43-acca-90ce06bdf33a
status: experimental
description: Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the
    DHCP server (restart required)
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
author: Dimitrios Slamaris
tags:
    - attack.defense_evasion
    - attack.t1073 # an old one
    - attack.t1574.002
    - attack.t1112
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        
        TargetObject:
            - '*\Services\DHCPServer\Parameters\CalloutDlls'
            - '*\Services\DHCPServer\Parameters\CalloutEnabled'
    condition: selection
falsepositives:
    - unknown
level: high

```