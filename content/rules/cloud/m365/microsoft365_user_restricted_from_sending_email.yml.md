---
title: "Microsoft 365 - User Restricted from Sending Email"
aliases:
  - "/rule/ff246f56-7f24-402a-baca-b86540e3925c"
ruleid: ff246f56-7f24-402a-baca-b86540e3925c

tags:
  - attack.initial_access
  - attack.t1199



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Security Compliance Center reported a user who exceeded sending limits of the service policies and because of this has been restricted from sending email.

<!--more-->


## Known false-positives

* <no value>



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_user_restricted_from_sending_email.yml))
```yaml
title: Microsoft 365 - User Restricted from Sending Email
id: ff246f56-7f24-402a-baca-b86540e3925c
status: experimental
description: Detects when a Security Compliance Center reported a user who exceeded sending limits of the service policies and because of this has been restricted from sending email.
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
        eventName: 'User restricted from sending email'
        status: success
    condition: selection
falsepositives:
    - 
level: medium
tags:
    - attack.initial_access
    - attack.t1199

```
