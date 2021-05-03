---
title: "smbexec.py Service Installation"
aliases:
  - "/rule/52a85084-6989-40c3-8f32-091e12e13f09"

tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1077
  - attack.t1021.002
  - attack.t1035
  - attack.t1569.002



date: Wed, 21 Mar 2018 10:44:14 +0100


---

Detects the use of smbexec.py tool by detecting a specific service installation

<!--more-->


## Known false-positives

* Penetration Test
* Unknown



## References

* https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/


## Raw rule
```yaml
title: smbexec.py Service Installation
id: 52a85084-6989-40c3-8f32-091e12e13f09
description: Detects the use of smbexec.py tool by detecting a specific service installation
author: Omer Faruk Celik
date: 2018/03/20
modified: 2020/08/23
references:
    - https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1077          # an old one
    - attack.t1021.002
    - attack.t1035          # an old one
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'BTOBTO'
        ServiceFileName: '*\execute.bat'
    condition: service_installation
fields:
    - ServiceName
    - ServiceFileName
falsepositives:
    - Penetration Test
    - Unknown
level: critical

```