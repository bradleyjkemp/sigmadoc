---
title: "Suspicious Inbox Forwarding"
aliases:
  - "/rule/6c220477-0b5b-4b25-bb90-66183b4089e8"
ruleid: 6c220477-0b5b-4b25-bb90-66183b4089e8

tags:
  - attack.exfiltration
  - attack.t1020



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported suspicious email forwarding rules, for example, if a user created an inbox rule that forwards a copy of all emails to an external address.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_suspicious_inbox_forwarding.yml))
```yaml
title: Suspicious Inbox Forwarding
id: 6c220477-0b5b-4b25-bb90-66183b4089e8
status: experimental
description: Detects when a Microsoft Cloud App Security reported suspicious email forwarding rules, for example, if a user created an inbox rule that forwards a copy of all emails to an external address.
author: Austin Songer @austinsonger
date: 2021/08/22
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
logsource:
    category: ThreatManagement
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Suspicious inbox forwarding'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.exfiltration
    - attack.t1020

```
