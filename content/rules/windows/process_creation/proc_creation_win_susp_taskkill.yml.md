---
title: "Suspicious Execution of Taskkill"
aliases:
  - "/rule/86085955-ea48-42a2-9dd3-85d4c36b167d"
ruleid: 86085955-ea48-42a2-9dd3-85d4c36b167d

tags:
  - attack.impact
  - attack.t1489



status: experimental





date: Sun, 26 Dec 2021 12:09:42 +0100


---

Adversaries may stop services or processes in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md#atomic-test-3---windows---stop-service-by-killing-process


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_taskkill.yml))
```yaml
title: Suspicious Execution of Taskkill
id: 86085955-ea48-42a2-9dd3-85d4c36b167d
status: experimental
description: Adversaries may stop services or processes in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server.
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md#atomic-test-3---windows---stop-service-by-killing-process
date: 2021/12/26
logsource:
    category: process_creation
    product: windows
detection:
    taskkill:
        Image|endswith: \taskkill.exe
        CommandLine|contains|all: 
            - /f 
            - /im
    condition: taskkill
falsepositives:
    - Unknown
level: low
tags:
    - attack.impact
    - attack.t1489

```
