---
title: "Advanced Port Scanner"
aliases:
  - "/rule/54773c5f-f1cc-4703-9126-2f797d96a69d"
ruleid: 54773c5f-f1cc-4703-9126-2f797d96a69d

tags:
  - attack.discovery
  - attack.t1046
  - attack.t1135



status: experimental





date: Sat, 18 Dec 2021 20:00:40 +0100


---

Detects the use of Advanced Port Scanner.

<!--more-->


## Known false-positives

* Legitimate administrative use
* Tools with similar commandline (very rare)



## References

* https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/Advanced%20Port%20Scanner


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_advanced_port_scanner.yml))
```yaml
title: Advanced Port Scanner
id: 54773c5f-f1cc-4703-9126-2f797d96a69d
status: experimental
description: Detects the use of Advanced Port Scanner.
references:
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/Advanced%20Port%20Scanner
author: Nasreddine Bencherchali @nas_bench
date: 2021/12/18
tags:
    - attack.discovery
    - attack.t1046
    - attack.t1135
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
       Image|contains: '\advanced_port_scanner'
    selection2:
       CommandLine|contains|all:
         - '/portable'
         - '/lng'
    condition: 1 of selection*
falsepositives:
    - Legitimate administrative use
    - Tools with similar commandline (very rare)
level: medium

```