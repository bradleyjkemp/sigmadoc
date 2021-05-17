---
title: "Hurricane Panda Activity"
aliases:
  - "/rule/0eb2107b-a596-422e-b123-b389d5594ed7"

tags:
  - attack.privilege_escalation
  - attack.g0009
  - attack.t1068



status: experimental



level: high



date: Wed, 31 Jan 2018 23:11:37 +0100


---

Detects Hurricane Panda Activity

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/


## Raw rule
```yaml
title: Hurricane Panda Activity
id: 0eb2107b-a596-422e-b123-b389d5594ed7
author: Florian Roth
date: 2019/03/04
status: experimental
description: Detects Hurricane Panda Activity
references:
    - https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/
tags:
    - attack.privilege_escalation
    - attack.g0009
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* localgroup administrators admin /add'
            - '*\Win64.exe*'
    condition: selection
falsepositives:
    - Unknown
level: high

```
