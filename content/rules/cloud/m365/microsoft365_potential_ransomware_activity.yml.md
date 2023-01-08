---
title: "Microsoft 365 - Potential Ransomware Activity"
aliases:
  - "/rule/bd132164-884a-48f1-aa2d-c6d646b04c69"
ruleid: bd132164-884a-48f1-aa2d-c6d646b04c69

tags:
  - attack.impact
  - attack.t1486



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported when a user uploads files to the cloud that might be infected with ransomware.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_potential_ransomware_activity.yml))
```yaml
title: Microsoft 365 - Potential Ransomware Activity
id: bd132164-884a-48f1-aa2d-c6d646b04c69
status: experimental
description: Detects when a Microsoft Cloud App Security reported when a user uploads files to the cloud that might be infected with ransomware.
author: austinsonger
date: 2021/08/19
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
logsource:
    category: ThreatManagement
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Potential ransomware activity'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.impact
    - attack.t1486

```
