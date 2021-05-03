---
title: "SILENTTRINITY Stager Execution"
aliases:
  - "/rule/03552375-cc2c-4883-bbe4-7958d5a980be"

tags:
  - attack.command_and_control



date: Wed, 23 Oct 2019 18:08:30 +0300


---

Detects SILENTTRINITY stager use

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/byt3bl33d3r/SILENTTRINITY


## Raw rule
```yaml
action: global
title: SILENTTRINITY Stager Execution
id: 03552375-cc2c-4883-bbe4-7958d5a980be
status: experimental
description: Detects SILENTTRINITY stager use
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019/10/22
modified: 2020/09/06
tags:
    - attack.command_and_control
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - unknown
level: high
---
logsource:
    category: process_creation
    product: windows
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7

```
