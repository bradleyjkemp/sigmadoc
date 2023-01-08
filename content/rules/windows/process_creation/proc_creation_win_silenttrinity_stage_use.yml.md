---
title: "SILENTTRINITY Stager Execution"
aliases:
  - "/rule/03552375-cc2c-4883-bbe4-7958d5a980be"
ruleid: 03552375-cc2c-4883-bbe4-7958d5a980be

tags:
  - attack.command_and_control
  - attack.t1071



status: experimental





date: Wed, 23 Oct 2019 18:08:30 +0300


---

Detects SILENTTRINITY stager use

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/byt3bl33d3r/SILENTTRINITY


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_silenttrinity_stage_use.yml))
```yaml
title: SILENTTRINITY Stager Execution
id: 03552375-cc2c-4883-bbe4-7958d5a980be
status: experimental
description: Detects SILENTTRINITY stager use
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019/10/22
modified: 2021/09/19
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - unknown
level: high
```
