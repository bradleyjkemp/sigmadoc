---
title: "UAC Bypass Via Wsreset"
aliases:
  - "/rule/6ea3bf32-9680-422d-9f50-e90716b12a66"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Unfixed method for UAC bypass from windows 10. WSReset.exe file associated with the Windows Store. It will run a binary file contained in a low-privilege registry.

<!--more-->


## Known false-positives

* unknown



## References

* https://www.bleepingcomputer.com/news/security/trickbot-uses-a-new-windows-10-uac-bypass-to-launch-quietly
* https://lolbas-project.github.io/lolbas/Binaries/Wsreset


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_bypass_via_wsreset.yml))
```yaml
title: UAC Bypass Via Wsreset
id: 6ea3bf32-9680-422d-9f50-e90716b12a66
status: test
description: Unfixed method for UAC bypass from windows 10. WSReset.exe file associated with the Windows Store. It will run a binary file contained in a low-privilege registry.
author: oscd.community, Dmitry Uchakin
references:
  - https://www.bleepingcomputer.com/news/security/trickbot-uses-a-new-windows-10-uac-bypass-to-launch-quietly
  - https://lolbas-project.github.io/lolbas/Binaries/Wsreset
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|endswith:
      - '\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command'
  condition: selection
fields:
  - ComputerName
  - Image
  - EventType
  - TargetObject
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002

```
