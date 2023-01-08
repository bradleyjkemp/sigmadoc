---
title: "Non-privileged Usage of Reg or Powershell"
aliases:
  - "/rule/8f02c935-effe-45b3-8fc9-ef8696a9e41d"
ruleid: 8f02c935-effe-45b3-8fc9-ef8696a9e41d

tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Search for usage of reg or Powershell by non-priveleged users to modify service configuration in registry

<!--more-->


## Known false-positives

* Unknown



## References

* https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_non_priv_reg_or_ps.yml))
```yaml
title: Non-privileged Usage of Reg or Powershell
id: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
status: test
description: Search for usage of reg or Powershell by non-priveleged users to modify service configuration in registry
author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
references:
  - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  integrity_level:
    IntegrityLevel: 'Medium'
  reg:
    CommandLine|contains|all:
      - 'reg'
      - 'add'
  powershell_1:
    CommandLine|contains: 'powershell'
  powershell_2:
    CommandLine|contains:
      - 'set-itemproperty'
      - ' sp '
      - 'new-itemproperty'
  registry_folder:
    CommandLine|contains|all:
      - 'ControlSet'
      - 'Services'
  registry_key:
    CommandLine|contains:
      - 'ImagePath'
      - 'FailureCommand'
      - 'ServiceDLL'
  condition: integrity_level and (reg or powershell_1 and powershell_2) and registry_folder and registry_key
fields:
  - EventID
  - IntegrityLevel
  - CommandLine
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1112

```
