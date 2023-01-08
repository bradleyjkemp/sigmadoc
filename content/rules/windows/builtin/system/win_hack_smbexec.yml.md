---
title: "smbexec.py Service Installation"
aliases:
  - "/rule/52a85084-6989-40c3-8f32-091e12e13f09"
ruleid: 52a85084-6989-40c3-8f32-091e12e13f09

tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1021.002
  - attack.t1569.002



status: test





date: Wed, 21 Mar 2018 10:44:14 +0100


---

Detects the use of smbexec.py tool by detecting a specific service installation

<!--more-->


## Known false-positives

* Penetration Test
* Unknown



## References

* https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_hack_smbexec.yml))
```yaml
title: smbexec.py Service Installation
id: 52a85084-6989-40c3-8f32-091e12e13f09
status: test
description: Detects the use of smbexec.py tool by detecting a specific service installation
author: Omer Faruk Celik
references:
  - https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
date: 2018/03/20
modified: 2021/11/30
logsource:
  product: windows
  service: system
detection:
  service_installation:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ServiceName: 'BTOBTO'
    ServiceFileName|endswith: '\execute.bat'
  condition: service_installation
fields:
  - ServiceName
  - ServiceFileName
falsepositives:
  - Penetration Test
  - Unknown
level: critical
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1021.002
  - attack.t1569.002

```
