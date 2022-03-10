---
title: "Sysinternals SDelete Registry Keys"
aliases:
  - "/rule/9841b233-8df8-4ad7-9133-b0b4402a9014"


tags:
  - attack.defense_evasion
  - attack.t1070.004



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection to trigger for the creation or modification of .*\Software\Sysinternals\SDelete registry keys. Indicators of the use of Sysinternals SDelete tool.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/9
* https://threathunterplaybook.com/evals/apt29/detections/4.B.2_59A9AC92-124D-4C4B-A6BF-3121C98677C3.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_sysinternals_sdelete_registry_keys.yml))
```yaml
title: Sysinternals SDelete Registry Keys
id: 9841b233-8df8-4ad7-9133-b0b4402a9014
description: A General detection to trigger for the creation or modification of .*\Software\Sysinternals\SDelete registry keys. Indicators of the use of Sysinternals SDelete tool.
status: experimental
date: 2020/05/02
modified: 2021/05/12
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.defense_evasion
    - attack.t1070.004
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/9
    - https://threathunterplaybook.com/evals/apt29/detections/4.B.2_59A9AC92-124D-4C4B-A6BF-3121C98677C3.html
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: '\Software\Sysinternals\SDelete'
    condition: selection
falsepositives:
    - unknown
level: medium
```
