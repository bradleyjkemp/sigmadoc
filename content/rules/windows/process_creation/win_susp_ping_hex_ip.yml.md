---
title: "Ping Hex IP"
aliases:
  - "/rule/1a0d4aba-7668-4365-9ce4-6d79ab088dfd"

tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.t1027





level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a ping command that uses a hex encoded IP address

<!--more-->


## Known false-positives

* Unlikely, because no sane admin pings IP addresses in a hexadecimal form



## References

* https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna
* https://twitter.com/vysecurity/status/977198418354491392


## Raw rule
```yaml
title: Ping Hex IP
id: 1a0d4aba-7668-4365-9ce4-6d79ab088dfd
description: Detects a ping command that uses a hex encoded IP address
references:
    - https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna
    - https://twitter.com/vysecurity/status/977198418354491392
author: Florian Roth
date: 2018/03/23
modified: 2020/10/16
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '\ping.exe 0x'
            - '\ping 0x'
        Image|contains:
            - 'ping.exe'
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high

```
