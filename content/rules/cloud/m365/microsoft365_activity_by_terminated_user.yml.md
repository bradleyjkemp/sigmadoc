---
title: "Activity Performed by Terminated User"
aliases:
  - "/rule/2e669ed8-742e-4fe5-b3c4-5a59b486c2ee"


tags:
  - attack.impact



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported for users whose account were terminated in Azure AD, but still perform activities in other platforms such as AWS or Salesforce. This is especially relevant for users who use another account to manage resources, since these accounts are often not terminated when a user leaves the company.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_activity_by_terminated_user.yml))
```yaml
title: Activity Performed by Terminated User
id: 2e669ed8-742e-4fe5-b3c4-5a59b486c2ee
status: experimental
description: Detects when a Microsoft Cloud App Security reported for users whose account were terminated in Azure AD, but still perform activities in other platforms such as AWS or Salesforce. This is especially relevant for users who use another account to manage resources, since these accounts are often not terminated when a user leaves the company.
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
        eventName: 'Activity performed by terminated user'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.impact

```
