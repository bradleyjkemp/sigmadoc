---
title: "Activity from Infrequent Country"
aliases:
  - "/rule/0f2468a2-5055-4212-a368-7321198ee706"


tags:
  - attack.command_and_control
  - attack.t1573



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported when an activity occurs from a location that wasn't recently or never visited by any user in the organization.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_activity_from_infrequent_country.yml))
```yaml
title: Activity from Infrequent Country
id: 0f2468a2-5055-4212-a368-7321198ee706
status: experimental
description: Detects when a Microsoft Cloud App Security reported when an activity occurs from a location that wasn't recently or never visited by any user in the organization.
author: Austin Songer @austinsonger
date: 2021/08/23
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
logsource:
    category: ThreatManagement
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Activity from infrequent country'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.command_and_control
    - attack.t1573

```
