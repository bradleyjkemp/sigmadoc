---
title: "Logon from a Risky IP Address"
aliases:
  - "/rule/c191e2fa-f9d6-4ccf-82af-4f2aba08359f"


tags:
  - attack.initial_access
  - attack.t1078



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported when a user signs into your sanctioned apps from a risky IP address.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_logon_from_risky_ip_address.yml))
```yaml
title: Logon from a Risky IP Address
id: c191e2fa-f9d6-4ccf-82af-4f2aba08359f
status: experimental
description: Detects when a Microsoft Cloud App Security reported when a user signs into your sanctioned apps from a risky IP address.
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
        eventName: 'Log on from a risky IP address'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.initial_access
    - attack.t1078

```