---
title: "Google Workspace User Granted Admin Privileges"
aliases:
  - "/rule/2d1b83e4-17c6-4896-a37b-29140b40a788"
ruleid: 2d1b83e4-17c6-4896-a37b-29140b40a788

tags:
  - attack.persistence
  - attack.t1098



status: experimental





date: Mon, 23 Aug 2021 21:19:44 -0500


---

Detects when an Google Workspace user is granted admin privileges.

<!--more-->


## Known false-positives

* Google Workspace admin role privileges, may be modified by system administrators.



## References

* https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
* https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-user-settings#GRANT_ADMIN_PRIVILEGE


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gworkspace/gworkspace_user_granted_admin_privileges.yml))
```yaml
title: Google Workspace User Granted Admin Privileges
id: 2d1b83e4-17c6-4896-a37b-29140b40a788
description: Detects when an Google Workspace user is granted admin privileges. 
author: Austin Songer
status: experimental
date: 2021/08/23
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-user-settings#GRANT_ADMIN_PRIVILEGE
logsource:
  product: google_workspace
  service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName: 
            - GRANT_DELEGATED_ADMIN_PRIVILEGES
            - GRANT_ADMIN_PRIVILEGE
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1098
falsepositives:
 - Google Workspace admin role privileges, may be modified by system administrators.
```
