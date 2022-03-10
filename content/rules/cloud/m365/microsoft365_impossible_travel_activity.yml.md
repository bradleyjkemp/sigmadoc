---
title: "Microsoft 365 - Impossible Travel Activity"
aliases:
  - "/rule/d7eab125-5f94-43df-8710-795b80fa1189"


tags:
  - attack.initial_access
  - attack.t1078



status: test





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel.

<!--more-->


## Known false-positives

* <no value>



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_impossible_travel_activity.yml))
```yaml
title: Microsoft 365 - Impossible Travel Activity
id: d7eab125-5f94-43df-8710-795b80fa1189
status: test
description: Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel.
author: Austin Songer @austinsonger
references:
  - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
  - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
date: 2020/07/06
modified: 2021/11/27
logsource:
  category: ThreatManagement
  product: m365
detection:
  selection:
    eventSource: SecurityComplianceCenter
    eventName: 'Impossible travel activity'
    status: success
  condition: selection
falsepositives:
  -
level: medium
tags:
  - attack.initial_access
  - attack.t1078



```
