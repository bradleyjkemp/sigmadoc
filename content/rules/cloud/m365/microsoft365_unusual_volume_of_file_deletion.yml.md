---
title: "Microsoft 365 - Unusual Volume of File Deletion"
aliases:
  - "/rule/78a34b67-3c39-4886-8fb4-61c46dc18ecd"
ruleid: 78a34b67-3c39-4886-8fb4-61c46dc18ecd

tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported a user has deleted a unusual a large volume of files.

<!--more-->


## Known false-positives

* <no value>



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_unusual_volume_of_file_deletion.yml))
```yaml
title: Microsoft 365 - Unusual Volume of File Deletion
id: 78a34b67-3c39-4886-8fb4-61c46dc18ecd
status: experimental
description: Detects when a Microsoft Cloud App Security reported a user has deleted a unusual a large volume of files.
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
        eventName: 'Unusual volume of file deletion'
        status: success
    condition: selection
falsepositives:
    - 
level: medium
tags:
    - attack.impact
    - attack.t1485

```
