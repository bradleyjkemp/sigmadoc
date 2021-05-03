---
title: "Turla Group Lateral Movement"
aliases:
  - "/rule/c601f20d-570a-4cde-a7d6-e17f99cb8e7f"

tags:
  - attack.g0010
  - attack.execution
  - attack.t1059
  - attack.lateral_movement
  - attack.t1077
  - attack.t1021.002
  - attack.discovery
  - attack.t1083
  - attack.t1135



date: Wed, 8 Nov 2017 00:33:17 +0100


---

Detects automated lateral movement by Turla group

<!--more-->


## Known false-positives

* Unknown



## References

* https://securelist.com/the-epic-turla-operation/65545/


## Raw rule
```yaml
action: global
title: Turla Group Lateral Movement
id: c601f20d-570a-4cde-a7d6-e17f99cb8e7f
status: experimental
description: Detects automated lateral movement by Turla group
references:
    - https://securelist.com/the-epic-turla-operation/65545/
tags:
    - attack.g0010
    - attack.execution
    - attack.t1059
    - attack.lateral_movement
    - attack.t1077 # an old one
    - attack.t1021.002
    - attack.discovery
    - attack.t1083
    - attack.t1135
author: Markus Neis
date: 2017/11/07
modified: 2020/08/27
logsource:
    category: process_creation
    product: windows
falsepositives:
   - Unknown
---
detection:
   selection:
      CommandLine:
         - 'net use \\%DomainController%\C$ "P@ssw0rd" *'
         - 'dir c:\\*.doc* /s'
         - 'dir %TEMP%\\*.exe'
   condition: selection
level: critical
---
detection:
   netCommand1:
      CommandLine: 'net view /DOMAIN'
   netCommand2:
      CommandLine: 'net session'
   netCommand3:
      CommandLine: 'net share'
   timeframe: 1m
   condition: netCommand1 | near netCommand2 and netCommand3
level: medium

```