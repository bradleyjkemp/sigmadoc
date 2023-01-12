---
title: "User Added to Local Administrators"
aliases:
  - "/rule/c265cf08-3f99-46c1-8d59-328247057d57"
ruleid: c265cf08-3f99-46c1-8d59-328247057d57

tags:
  - attack.privilege_escalation
  - attack.t1078
  - attack.persistence
  - attack.t1098



status: stable





date: Tue, 14 Mar 2017 12:51:50 +0100


---

This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity

<!--more-->


## Known false-positives

* Legitimate administrative activity




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_user_added_to_local_administrators.yml))
```yaml
title: User Added to Local Administrators
id: c265cf08-3f99-46c1-8d59-328247057d57
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation
    activity
status: stable
author: Florian Roth
date: 2017/03/14
modified: 2021/01/17
tags:
    - attack.privilege_escalation
    - attack.t1078
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        Provider_Name: Microsoft-Windows-Security-Auditing
        EventID: 4732
    selection_group1:
        TargetUserName|startswith: 'Administr'
    selection_group2:
        TargetSid: 'S-1-5-32-544'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and (1 of selection_group*) and not filter
falsepositives:
    - Legitimate administrative activity
level: medium

```