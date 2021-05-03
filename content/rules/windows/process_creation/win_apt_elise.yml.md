---
title: "Elise Backdoor"
aliases:
  - "/rule/e507feb7-5f73-4ef6-a970-91bb6f6d744f"

tags:
  - attack.g0030
  - attack.g0050
  - attack.s0081
  - attack.execution
  - attack.t1059
  - attack.t1059.003



date: Wed, 31 Jan 2018 23:11:37 +0100


---

Detects Elise backdoor acitivty as used by APT32

<!--more-->


## Known false-positives

* Unknown



## References

* https://community.rsa.com/community/products/netwitness/blog/2018/02/13/lotus-blossom-continues-asean-targeting


## Raw rule
```yaml
title: Elise Backdoor
id: e507feb7-5f73-4ef6-a970-91bb6f6d744f
status: experimental
description: Detects Elise backdoor acitivty as used by APT32
references:
    - https://community.rsa.com/community/products/netwitness/blog/2018/02/13/lotus-blossom-continues-asean-targeting
tags:
    - attack.g0030
    - attack.g0050
    - attack.s0081
    - attack.execution
    - attack.t1059 # an old one
    - attack.t1059.003
author: Florian Roth
date: 2018/01/31
modified: 2020/08/26
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: 'C:\Windows\SysWOW64\cmd.exe'
        CommandLine: '*\Windows\Caches\NavShExt.dll *'
    selection2:
        CommandLine: '*\AppData\Roaming\MICROS~1\Windows\Caches\NavShExt.dll,Setting'
    condition: 1 of them
falsepositives:
    - Unknown
level: critical

```
