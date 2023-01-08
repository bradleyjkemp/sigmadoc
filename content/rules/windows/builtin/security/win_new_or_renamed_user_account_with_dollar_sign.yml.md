---
title: "New or Renamed User Account with '$' in Attribute 'SamAccountName'."
aliases:
  - "/rule/cfeed607-6aa4-4bbd-9627-b637deb723c8"
ruleid: cfeed607-6aa4-4bbd-9627-b637deb723c8

tags:
  - attack.defense_evasion
  - attack.t1036



status: experimental





date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects possible bypass EDR and SIEM via abnormal user account name.

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_new_or_renamed_user_account_with_dollar_sign.yml))
```yaml
title: New or Renamed User Account with '$' in Attribute 'SamAccountName'.
id: cfeed607-6aa4-4bbd-9627-b637deb723c8
status: experimental
description: Detects possible bypass EDR and SIEM via abnormal user account name.
tags:
    - attack.defense_evasion
    - attack.t1036
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2021/07/07
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 
            - 4720 # create user
            - 4781 # rename user
        SamAccountName|contains: '$'    
    condition: selection
fields:
    - EventID
    - SamAccountName
    - SubjectUserName
falsepositives:
    - Unknown
level: high

```
