---
title: "New Application in AppCompat"
aliases:
  - "/rule/60936b49-fca0-4f32-993d-7415edcf9a5d"


tags:
  - attack.execution
  - attack.t1204.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection for a new application in AppCompat. This indicates an application executing for the first time on an endpoint.

<!--more-->


## Known false-positives

* This rule is to explore new applications on an endpoint. False positives depends on the organization.
* Newly setup system.
* Legitimate installation of new application.



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/1
* https://threathunterplaybook.com/evals/apt29/detections/1.A.1_DFD6A782-9BDB-4550-AB6B-525E825B095E.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_new_application_appcompat.yml))
```yaml
title: New Application in AppCompat
id: 60936b49-fca0-4f32-993d-7415edcf9a5d
status: test
description: A General detection for a new application in AppCompat. This indicates an application executing for the first time on an endpoint.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/1
  - https://threathunterplaybook.com/evals/apt29/detections/1.A.1_DFD6A782-9BDB-4550-AB6B-525E825B095E.html
date: 2020/05/02
modified: 2021/11/27
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains: '\AppCompatFlags\Compatibility Assistant\Store\'
  condition: selection
falsepositives:
  - This rule is to explore new applications on an endpoint. False positives depends on the organization.
  - Newly setup system.
  - Legitimate installation of new application.
level: informational
tags:
  - attack.execution
  - attack.t1204.002

```