---
title: "Elise Backdoor"
aliases:
  - "/rule/e507feb7-5f73-4ef6-a970-91bb6f6d744f"
ruleid: e507feb7-5f73-4ef6-a970-91bb6f6d744f

tags:
  - attack.g0030
  - attack.g0050
  - attack.s0081
  - attack.execution
  - attack.t1059.003



status: test





date: Wed, 31 Jan 2018 23:11:37 +0100


---

Detects Elise backdoor acitivty as used by APT32

<!--more-->


## Known false-positives

* Unknown



## References

* https://community.rsa.com/community/products/netwitness/blog/2018/02/13/lotus-blossom-continues-asean-targeting


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_elise.yml))
```yaml
title: Elise Backdoor
id: e507feb7-5f73-4ef6-a970-91bb6f6d744f
status: test
description: Detects Elise backdoor acitivty as used by APT32
author: Florian Roth
references:
  - https://community.rsa.com/community/products/netwitness/blog/2018/02/13/lotus-blossom-continues-asean-targeting
date: 2018/01/31
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image: 'C:\Windows\SysWOW64\cmd.exe'
    CommandLine|contains: '\Windows\Caches\NavShExt.dll '
  selection2:
    CommandLine|endswith: '\AppData\Roaming\MICROS~1\Windows\Caches\NavShExt.dll,Setting'
  condition: 1 of selection*
falsepositives:
  - Unknown
level: critical
tags:
  - attack.g0030
  - attack.g0050
  - attack.s0081
  - attack.execution
  - attack.t1059.003

```
