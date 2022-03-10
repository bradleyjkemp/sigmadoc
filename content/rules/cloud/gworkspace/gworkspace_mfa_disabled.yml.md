---
title: "Google Workspace MFA Disabled"
aliases:
  - "/rule/780601d1-6376-4f2a-884e-b8d45599f78c"


tags:
  - attack.impact



status: experimental





date: Thu, 26 Aug 2021 20:28:35 -0500


---

Detects when multi-factor authentication (MFA) is disabled.

<!--more-->


## Known false-positives

* MFA may be disabled and performed by a system administrator.



## References

* https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
* https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings#ENFORCE_STRONG_AUTHENTICATION
* https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings?hl=en#ALLOW_STRONG_AUTHENTICATION


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gworkspace/gworkspace_mfa_disabled.yml))
```yaml
title: Google Workspace MFA Disabled
id: 780601d1-6376-4f2a-884e-b8d45599f78c
description: Detects when multi-factor authentication (MFA) is disabled.
author: Austin Songer
status: experimental
date: 2021/08/26
modified: 2021/12/02
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings#ENFORCE_STRONG_AUTHENTICATION
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings?hl=en#ALLOW_STRONG_AUTHENTICATION
logsource:
  product: google_workspace
  service: google_workspace.admin
detection:
    selection_base:
        eventService: admin.googleapis.com
        eventName: 
            - ENFORCE_STRONG_AUTHENTICATION
            - ALLOW_STRONG_AUTHENTICATION
    selection_eventValue:
        new_value: 'false'
    condition: all of selection*
level: medium
tags:
    - attack.impact
falsepositives:
 - MFA may be disabled and performed by a system administrator.
 
```
