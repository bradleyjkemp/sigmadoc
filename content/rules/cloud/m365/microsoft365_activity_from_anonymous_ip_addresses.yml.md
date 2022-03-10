---
title: "Activity from Anonymous IP Addresses"
aliases:
  - "/rule/d8b0a4fe-07a8-41be-bd39-b14afa025d95"


tags:
  - attack.command_and_control
  - attack.t1573



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported when users were active from an IP address that has been identified as an anonymous proxy IP address.

<!--more-->


## Known false-positives

* User using a VPN or Proxy



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_activity_from_anonymous_ip_addresses.yml))
```yaml
title: Activity from Anonymous IP Addresses
id: d8b0a4fe-07a8-41be-bd39-b14afa025d95
status: experimental
description: Detects when a Microsoft Cloud App Security reported when users were active from an IP address that has been identified as an anonymous proxy IP address.
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
        eventName: 'Activity from anonymous IP addresses'
        status: success
    condition: selection
falsepositives:
    - User using a VPN or Proxy
level: medium
tags:
    - attack.command_and_control
    - attack.t1573

```
