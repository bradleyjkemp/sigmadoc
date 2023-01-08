---
title: "Suspicious Execution of Systeminfo"
aliases:
  - "/rule/0ef56343-059e-4cb6-adc1-4c3c967c5e46"
ruleid: 0ef56343-059e-4cb6-adc1-4c3c967c5e46

tags:
  - attack.discovery
  - attack.t1082



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

Use of systeminfo to get information

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md#atomic-test-1---system-information-discovery
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_systeminfo.yml))
```yaml
title: Suspicious Execution of Systeminfo 
id: 0ef56343-059e-4cb6-adc1-4c3c967c5e46
status: experimental
description: Use of systeminfo to get information
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md#atomic-test-1---system-information-discovery
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \systeminfo.exe
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1082

```
