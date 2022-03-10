---
title: "Activity from Suspicious IP Addresses"
aliases:
  - "/rule/a3501e8e-af9e-43c6-8cd6-9360bdaae498"


tags:
  - attack.command_and_control
  - attack.t1573



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported users were active from an IP address identified as risky by Microsoft Threat Intelligence. These IP addresses are involved in malicious activities, such as Botnet C&C, and may indicate compromised account.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_from_suspicious_ip_addresses.yml))
```yaml
title: Activity from Suspicious IP Addresses
id: a3501e8e-af9e-43c6-8cd6-9360bdaae498
status: experimental
description: Detects when a Microsoft Cloud App Security reported users were active from an IP address identified as risky by Microsoft Threat Intelligence. These IP addresses are involved in malicious activities, such as Botnet C&C, and may indicate compromised account. 
author: Austin Songer @austinsonger
date: 2021/08/23
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
logsource:
    category: ThreatDetection
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Activity from suspicious IP addresses'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.command_and_control
    - attack.t1573

```
