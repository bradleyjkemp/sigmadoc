---
title: "HH.exe Execution"
aliases:
  - "/rule/68c8acb4-1b60-4890-8e82-3ddf7a6dba84"

tags:
  - attack.defense_evasion
  - attack.t1218.001
  - attack.execution
  - attack.t1223



status: experimental



level: high



date: Mon, 28 Oct 2019 11:59:49 +0100


---

Identifies usage of hh.exe executing recently modified .chm files.

<!--more-->


## Known false-positives

* unlike



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1223/T1223.yaml
* https://eqllib.readthedocs.io/en/latest/analytics/b25aa548-7937-11e9-8f5c-d46d6d62a49e.html


## Raw rule
```yaml
title: HH.exe Execution
id: 68c8acb4-1b60-4890-8e82-3ddf7a6dba84
description: Identifies usage of hh.exe executing recently modified .chm files.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Dan Beavin), oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1223/T1223.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/b25aa548-7937-11e9-8f5c-d46d6d62a49e.html
date: 2019/10/24
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.t1218.001
    - attack.execution  # an old one
    - attack.t1223  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\hh.exe'
        CommandLine|contains: '.chm'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - unlike
level: high

```
