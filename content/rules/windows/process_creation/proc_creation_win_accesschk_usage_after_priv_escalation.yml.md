---
title: "Accesschk Usage After Privilege Escalation"
aliases:
  - "/rule/c625d754-6a3d-4f65-9c9a-536aea960d37"


tags:
  - attack.discovery
  - attack.t1069.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Accesschk is an access and privilege audit tool developed by SysInternal and often being used by attacker to verify if a privilege escalation process successful or not

<!--more-->


## Known false-positives

* System administrator Usage
* Penetration test



## References

* https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-43-638.jpg


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_accesschk_usage_after_priv_escalation.yml))
```yaml
title: Accesschk Usage After Privilege Escalation
id: c625d754-6a3d-4f65-9c9a-536aea960d37
status: test
description: Accesschk is an access and privilege audit tool developed by SysInternal and often being used by attacker to verify if a privilege escalation process successful or not
author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
references:
  - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-43-638.jpg
date: 2020/10/13
modified: 2021/11/27
logsource:
  product: windows
  category: process_creation
detection:
  integrity_level:
    IntegrityLevel: 'Medium'
  product:
    Product|endswith: 'AccessChk'
  description:
    Description|contains: 'Reports effective permissions'
  condition: integrity_level and (product or description)
fields:
  - IntegrityLevel
  - Product
  - Description
falsepositives:
  - System administrator Usage
  - Penetration test
level: high
tags:
  - attack.discovery
  - attack.t1069.001

```
