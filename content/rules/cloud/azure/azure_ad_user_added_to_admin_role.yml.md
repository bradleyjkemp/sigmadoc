---
title: "User Added to an Administrator's Azure AD Role"
aliases:
  - "/rule/ebbeb024-5b1d-4e16-9c0c-917f86c708a7"


tags:
  - attack.persistence
  - attack.t1098.003



status: experimental





date: Sat, 25 Sep 2021 21:57:10 +0200


---

User Added to an Administrator's Azure AD Role

<!--more-->


## Known false-positives

* PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.



## References

* https://attack.mitre.org/techniques/T1098/003/
* https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_ad_user_added_to_admin_role.yml))
```yaml
title: User Added to an Administrator's Azure AD Role
id: ebbeb024-5b1d-4e16-9c0c-917f86c708a7
description: User Added to an Administrator's Azure AD Role
author: Raphaël CALVET, @MetallicHack
date: 2021/10/04
references:
    - https://attack.mitre.org/techniques/T1098/003/
    - https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/
logsource:
    product: azure
    service: azure.activitylogs
detection: 
   selection: 
       Operation: 'Add member to role.'
       Workload: 'AzureActiveDirectory'
       ModifiedProperties{}.NewValue|endswith:
           - 'Admins'
           - 'Administrator'
   condition: selection
falsepositives:
    - PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled. 
level: medium
status: experimental
tags: 
    - attack.persistence
    - attack.t1098.003

```
