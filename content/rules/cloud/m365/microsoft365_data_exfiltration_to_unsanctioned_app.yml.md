---
title: "Data Exfiltration to Unsanctioned Apps"
aliases:
  - "/rule/2b669496-d215-47d8-bd9a-f4a45bf07cda"


tags:
  - attack.exfiltration
  - attack.t1537



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported when a user or IP address uses an app that is not sanctioned to perform an activity that resembles an attempt to exfiltrate information from your organization.

<!--more-->


## Known false-positives

* <no value>



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_data_exfiltration_to_unsanctioned_app.yml))
```yaml
title: Data Exfiltration to Unsanctioned Apps
id: 2b669496-d215-47d8-bd9a-f4a45bf07cda
status: experimental
description: Detects when a Microsoft Cloud App Security reported when a user or IP address uses an app that is not sanctioned to perform an activity that resembles an attempt to exfiltrate information from your organization.
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
        eventName: 'Data exfiltration to unsanctioned apps'
        status: success
    condition: selection
falsepositives:
    - 
level: medium
tags:
    - attack.exfiltration
    - attack.t1537

```