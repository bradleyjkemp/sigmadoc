---
title: "Modification of ld.so.preload"
aliases:
  - "/rule/4b3cb710-5e83-4715-8c45-8b2b5b3e5751"

tags:
  - attack.defense_evasion
  - attack.t1574.006



date: Mon, 28 Oct 2019 11:59:49 +0100


---

Identifies modification of ld.so.preload for shared object injection. This technique is used by attackers to load arbitrary code into processes.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.006/T1574.006.yaml
* https://eqllib.readthedocs.io/en/latest/analytics/fd9b987a-1101-4ed3-bda6-a70300eaf57e.html


## Raw rule
```yaml
title: Modification of ld.so.preload
id: 4b3cb710-5e83-4715-8c45-8b2b5b3e5751
status: experimental
description: Identifies modification of ld.so.preload for shared object injection. This technique is used by attackers to load arbitrary code into processes.
author: E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.006/T1574.006.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/fd9b987a-1101-4ed3-bda6-a70300eaf57e.html
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name: '/etc/ld.so.preload'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1574.006
```