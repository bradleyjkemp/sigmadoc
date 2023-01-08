---
title: "DNS ServerLevelPluginDll Install"
aliases:
  - "/rule/e61e8a88-59a9-451c-874e-70fcc9740d67"
ruleid: e61e8a88-59a9-451c-874e-70fcc9740d67

tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.t1112



status: experimental





date: Mon, 8 May 2017 13:39:50 +0200


---

Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)

<!--more-->


## Known false-positives

* unknown



## References

* https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_dns_serverlevelplugindll.yml))
```yaml
title: DNS ServerLevelPluginDll Install
id: e61e8a88-59a9-451c-874e-70fcc9740d67
status: experimental
description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server
    (restart required)
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
date: 2017/05/08
modified: 2021/09/12
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    dnsregmod: 
        TargetObject|endswith: '\services\DNS\Parameters\ServerLevelPluginDll'
    condition: dnsregmod
falsepositives:
    - unknown
level: high
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
```
