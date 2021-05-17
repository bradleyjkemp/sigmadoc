---
title: "Suspicious DNS Query with B64 Encoded String"
aliases:
  - "/rule/4153a907-2451-4e4f-a578-c52bb6881432"

tags:
  - attack.exfiltration
  - attack.t1048
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071
  - attack.t1071.004



status: experimental



level: medium



date: Thu, 10 May 2018 14:08:39 +0200


---

Detects suspicious DNS queries using base64 encoding

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/krmaxwell/dns-exfiltration


## Raw rule
```yaml
title: Suspicious DNS Query with B64 Encoded String
id: 4153a907-2451-4e4f-a578-c52bb6881432
status: experimental
description: Detects suspicious DNS queries using base64 encoding
author: Florian Roth
date: 2018/05/10
modified: 2020/08/27
references:
    - https://github.com/krmaxwell/dns-exfiltration
logsource:
    category: dns
detection:
    selection:
        query:
            - '*==.*'
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.exfiltration
    - attack.t1048 # an old one
    - attack.t1048.003
    - attack.command_and_control
    - attack.t1071 # an old one
    - attack.t1071.004
```
