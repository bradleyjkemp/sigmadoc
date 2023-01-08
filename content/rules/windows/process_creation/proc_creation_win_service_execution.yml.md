---
title: "Service Execution"
aliases:
  - "/rule/2a072a96-a086-49fa-bcb5-15cc5a619093"
ruleid: 2a072a96-a086-49fa-bcb5-15cc5a619093

tags:
  - attack.execution
  - attack.t1569.002



status: test





date: Tue, 29 Oct 2019 20:58:52 +0300


---

Detects manual service execution (start) via system utilities.

<!--more-->


## Known false-positives

* Legitimate administrator or user executes a service for legitimate reasons.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_service_execution.yml))
```yaml
title: Service Execution
id: 2a072a96-a086-49fa-bcb5-15cc5a619093
status: test
description: Detects manual service execution (start) via system utilities.
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md
date: 2019/10/21
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains: ' start '     # space character after the 'start' keyword indicates that a service name follows, in contrast to `net start` discovery expression 
  condition: selection
falsepositives:
  - Legitimate administrator or user executes a service for legitimate reasons.
level: low
tags:
  - attack.execution
  - attack.t1569.002

```
