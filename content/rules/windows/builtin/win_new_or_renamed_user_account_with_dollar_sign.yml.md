---
title: "New or Renamed User Account with '$' in Attribute 'SamAccountName'."
aliases:
  - "/rule/cfeed607-6aa4-4bbd-9627-b637deb723c8"

tags:
  - attack.defense_evasion
  - attack.t1036



status: experimental



level: high



date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects possible bypass EDR and SIEM via abnormal user account name.

<!--more-->


## Known false-positives

* Unkown




## Raw rule
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
modified: 2019/11/13
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 
            - 4720 # create user
            - 4781 # rename user
        UserName|contains: '$'    #SamAccountName
    condition: selection
fields:
    - EventID
    - UserName
    - SubjectAccountName
falsepositives:
    - Unkown
level: high

```
