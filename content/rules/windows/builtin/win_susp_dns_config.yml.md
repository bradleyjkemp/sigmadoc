---
title: "DNS Server Error Failed Loading the ServerLevelPluginDLL"
aliases:
  - "/rule/cbe51394-cd93-4473-b555-edf0144952d9"

tags:
  - attack.defense_evasion
  - attack.t1073
  - attack.t1574.002



date: Mon, 8 May 2017 13:09:50 +0200


---

This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded

<!--more-->


## Known false-positives

* Unknown



## References

* https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
* https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx
* https://twitter.com/gentilkiwi/status/861641945944391680


## Raw rule
```yaml
title: DNS Server Error Failed Loading the ServerLevelPluginDLL
id: cbe51394-cd93-4473-b555-edf0144952d9
description: This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded
status: experimental
date: 2017/05/08
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
    - https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx
    - https://twitter.com/gentilkiwi/status/861641945944391680
tags:
    - attack.defense_evasion
    - attack.t1073           # an old one
    - attack.t1574.002
author: Florian Roth
logsource:
    product: windows
    service: dns-server
detection:
    selection:
        EventID:
            - 150
            - 770
    condition: selection
falsepositives:
    - Unknown
level: critical



```