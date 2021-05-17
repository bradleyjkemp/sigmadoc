---
title: "Service Execution"
aliases:
  - "/rule/2a072a96-a086-49fa-bcb5-15cc5a619093"

tags:
  - attack.execution
  - attack.t1035
  - attack.t1569.002



status: experimental



level: low



date: Tue, 29 Oct 2019 20:58:52 +0300


---

Detects manual service execution (start) via system utilities

<!--more-->


## Known false-positives

* Legitimate administrator or user executes a service for legitimate reason



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml


## Raw rule
```yaml
title: Service Execution
id: 2a072a96-a086-49fa-bcb5-15cc5a619093
status: experimental
description: Detects manual service execution (start) via system utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: ' start ' # space character after the 'start' keyword indicates that a service name follows, in contrast to `net start` discovery expression 
    condition: selection
falsepositives:
    - Legitimate administrator or user executes a service for legitimate reason
level: low
tags:
    - attack.execution
    - attack.t1035 # an old one
    - attack.t1569.002

```
