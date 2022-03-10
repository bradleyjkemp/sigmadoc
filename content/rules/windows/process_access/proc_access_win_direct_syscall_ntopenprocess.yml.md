---
title: "Direct Syscall of NtOpenProcess"
aliases:
  - "/rule/3f3f3506-1895-401b-9cc3-e86b16e630d0"


tags:
  - attack.execution
  - attack.t1106



status: experimental





date: Wed, 28 Jul 2021 15:14:30 +0200


---

Detects the usage of the direct syscall of NtOpenProcess which might be done from a CobaltStrike BOF.

<!--more-->


## Known false-positives

* unknown



## References

* https://medium.com/falconforce/falconfriday-direct-system-calls-and-cobalt-strike-bofs-0xff14-741fa8e1bdd6


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_direct_syscall_ntopenprocess.yml))
```yaml
title: Direct Syscall of NtOpenProcess
id: 3f3f3506-1895-401b-9cc3-e86b16e630d0 
description: Detects the usage of the direct syscall of NtOpenProcess which might be done from a CobaltStrike BOF.
references:
    - https://medium.com/falconforce/falconfriday-direct-system-calls-and-cobalt-strike-bofs-0xff14-741fa8e1bdd6
status: experimental
author: Christian Burkard
date: 2021/07/28
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|startswith: 'UNKNOWN'
    condition: selection
falsepositives:
    - unknown
level: critical
tags:
    - attack.execution
    - attack.t1106 

```
