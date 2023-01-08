---
title: "Lateral Movement Indicator ConDrv"
aliases:
  - "/rule/29d31aee-30f4-4006-85a9-a4a02d65306c"
ruleid: 29d31aee-30f4-4006-85a9-a4a02d65306c

tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1021
  - attack.t1059



status: deprecated





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This event was observed on the target host during lateral movement. The process name within the event contains the process spawned post compromise. Account Name within the event contains the compromised user account name. This event should to be correlated with 4624 and 4688 for further intrusion context.

<!--more-->


## Known false-positives

* legal admin action
* Penetration tests where lateral movement has occurred. This event will be created on the target host.



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/wmiexec-vbs.htm
* https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_lateral_movement_condrv.yml))
```yaml
title: Lateral Movement Indicator ConDrv
id: 29d31aee-30f4-4006-85a9-a4a02d65306c
status: deprecated #Too many FP
description: This event was observed on the target host during lateral movement. The process name within the event contains the process spawned post compromise. Account Name within the event contains the compromised user account name. This event should to be correlated with 4624 and 4688 for further intrusion context.
author: Janantha Marasinghe
date: 2021/04/27
modified: 2021/12/09
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/wmiexec-vbs.htm
    - https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.html
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1021  
    - attack.t1059
logsource:
    product: windows
    service: security
detection:
    selection:
          EventID: 4674
          ObjectServer: 'Security'
          ObjectType: 'File'
          ObjectName: '\Device\ConDrv'
    condition: selection
falsepositives:
    - legal admin action
    - Penetration tests where lateral movement has occurred. This event will be created on the target host.
level: low

```
