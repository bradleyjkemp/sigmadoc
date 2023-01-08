---
title: "Suspicious Query of MachineGUID"
aliases:
  - "/rule/f5240972-3938-4e56-8e4b-e33893176c1f"
ruleid: f5240972-3938-4e56-8e4b-e33893176c1f

tags:
  - attack.discovery
  - attack.t1082



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

Use of reg to get MachineGuid information

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_machineguid.yml))
```yaml
title: Suspicious Query of MachineGUID
id: f5240972-3938-4e56-8e4b-e33893176c1f
status: experimental
description: Use of reg to get MachineGuid information
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \reg.exe
        CommandLine|contains|all:
            - 'SOFTWARE\Microsoft\Cryptography'
            - '/v '
            - 'MachineGuid'  
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1082

```
