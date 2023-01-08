---
title: "Creation of a Local Hidden User Account by Registry"
aliases:
  - "/rule/460479f3-80b7-42da-9c43-2cc1d54dbccd"
ruleid: 460479f3-80b7-42da-9c43-2cc1d54dbccd

tags:
  - attack.persistence
  - attack.t1136.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Sysmon registry detection of a local hidden user account.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1387530414185664538


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_add_local_hidden_user.yml))
```yaml
title: Creation of a Local Hidden User Account by Registry
id: 460479f3-80b7-42da-9c43-2cc1d54dbccd
description: Sysmon registry detection of a local hidden user account.
status: experimental
date: 2021/05/03
modified: 2021/05/12
author: Christian Burkard
tags:
    - attack.persistence
    - attack.t1136.001
references:
    - https://twitter.com/SBousseaden/status/1387530414185664538
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|startswith: 'HKLM\SAM\SAM\Domains\Account\Users\Names\'
        TargetObject|endswith: '$'
        Image|endswith: 'lsass.exe'
    condition: selection
falsepositives:
    - unknown
level: high

```
