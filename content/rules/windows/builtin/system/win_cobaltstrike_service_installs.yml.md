---
title: "CobaltStrike Service Installations"
aliases:
  - "/rule/5a105d34-05fc-401e-8553-272b45c1522d"
ruleid: 5a105d34-05fc-401e-8553-272b45c1522d

tags:
  - attack.execution
  - attack.privilege_escalation
  - attack.lateral_movement
  - attack.t1021.002
  - attack.t1543.003
  - attack.t1569.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.sans.org/webcasts/119395
* https://www.crowdstrike.com/blog/getting-the-bacon-from-cobalt-strike-beacon/
* https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_cobaltstrike_service_installs.yml))
```yaml
title: CobaltStrike Service Installations
id: 5a105d34-05fc-401e-8553-272b45c1522d
description: Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement
status: experimental
author: Florian Roth, Wojciech Lesicki
references:
    - https://www.sans.org/webcasts/119395
    - https://www.crowdstrike.com/blog/getting-the-bacon-from-cobalt-strike-beacon/
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
date: 2021/05/26
modified: 2021/09/30
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.lateral_movement 
    - attack.t1021.002
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection_id:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection1:
        ImagePath|contains|all: 
            - 'ADMIN$'
            - '.exe'
    selection2:
        ImagePath|contains|all: 
            - '%COMSPEC%'
            - 'start'
            - 'powershell'
    selection3:
        ImagePath|contains: 'powershell -nop -w hidden -encodedcommand'
    selection4:
        ImagePath|base64offset|contains: "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:"
    condition: selection_id and (selection1 or selection2 or selection3 or selection4)
falsepositives:
    - Unknown
level: critical
```