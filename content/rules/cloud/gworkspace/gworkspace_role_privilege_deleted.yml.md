---
title: "Google Workspace Role Privilege Deleted"
aliases:
  - "/rule/bf638ef7-4d2d-44bb-a1dc-a238252e6267"
ruleid: bf638ef7-4d2d-44bb-a1dc-a238252e6267

tags:
  - attack.impact



status: experimental





date: Mon, 23 Aug 2021 21:19:44 -0500


---

Detects when an a role privilege is deleted in Google Workspace.

<!--more-->


## Known false-positives

* Unknown



## References

* https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
* https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gworkspace/gworkspace_role_privilege_deleted.yml))
```yaml
title: Google Workspace Role Privilege Deleted
id: bf638ef7-4d2d-44bb-a1dc-a238252e6267
description: Detects when an a role privilege is deleted in Google Workspace.
author: Austin Songer
status: experimental
date: 2021/08/24
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings
logsource:
  product: google_workspace
  service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName: REMOVE_PRIVILEGE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown
 

```
