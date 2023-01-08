---
title: "Suspicious OAuth App File Download Activities"
aliases:
  - "/rule/ee111937-1fe7-40f0-962a-0eb44d57d174"
ruleid: ee111937-1fe7-40f0-962a-0eb44d57d174

tags:
  - attack.exfiltration



status: experimental





date: Tue, 6 Jul 2021 16:55:54 -0500


---

Detects when a Microsoft Cloud App Security reported when an app downloads multiple files from Microsoft SharePoint or Microsoft OneDrive in a manner that is unusual for the user.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
* https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_suspicious_oauth_app_file_download_activities.yml))
```yaml
title: Suspicious OAuth App File Download Activities
id: ee111937-1fe7-40f0-962a-0eb44d57d174
status: experimental
description: Detects when a Microsoft Cloud App Security reported when an app downloads multiple files from Microsoft SharePoint or Microsoft OneDrive in a manner that is unusual for the user.
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
        eventName: 'Suspicious OAuth app file download activities'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.exfiltration

```
