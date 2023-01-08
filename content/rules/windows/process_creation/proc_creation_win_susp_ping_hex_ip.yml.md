---
title: "Ping Hex IP"
aliases:
  - "/rule/1a0d4aba-7668-4365-9ce4-6d79ab088dfd"
ruleid: 1a0d4aba-7668-4365-9ce4-6d79ab088dfd

tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.t1027



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a ping command that uses a hex encoded IP address

<!--more-->


## Known false-positives

* Unlikely, because no sane admin pings IP addresses in a hexadecimal form



## References

* https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.can
* https://twitter.com/vysecurity/status/977198418354491392


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ping_hex_ip.yml))
```yaml
title: Ping Hex IP
id: 1a0d4aba-7668-4365-9ce4-6d79ab088dfd
status: test
description: Detects a ping command that uses a hex encoded IP address
author: Florian Roth
references:
  - https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.can
  - https://twitter.com/vysecurity/status/977198418354491392
date: 2018/03/23
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\ping.exe'
    CommandLine|contains: '0x'
  condition: selection
fields:
  - ParentCommandLine
falsepositives:
  - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high
tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.t1027

```
