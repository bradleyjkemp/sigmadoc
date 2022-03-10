---
title: "Communication To Mega.nz"
aliases:
  - "/rule/fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4"


tags:
  - attack.exfiltration
  - attack.t1567.001



status: experimental





date: Mon, 6 Dec 2021 18:35:04 +0100


---

Detects an executable accessing mega.co.nz, which could be a sign of forbidden file sharing use of data exfiltration by malicious actors

<!--more-->


## Known false-positives

* Legitimate use of mega.nz uploaders and tools



## References

* https://megatools.megous.com/
* https://www.mandiant.com/resources/russian-targeting-gov-business


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_mega_nz.yml))
```yaml
title: Communication To Mega.nz
id: fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4
status: experimental
description: Detects an executable accessing mega.co.nz, which could be a sign of forbidden file sharing use of data exfiltration by malicious actors
author: Florian Roth
references:
  - https://megatools.megous.com/
  - https://www.mandiant.com/resources/russian-targeting-gov-business
date: 2021/12/06
tags:
  - attack.exfiltration
  - attack.t1567.001
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    DestinationHostname|endswith: 'api.mega.co.nz'
  condition: selection
falsepositives:
  - Legitimate use of mega.nz uploaders and tools
level: high

```
