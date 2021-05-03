---
title: "Regsvr32 Anomaly"
aliases:
  - "/rule/8e2b24c9-4add-46a0-b4bb-0057b4e6187d"

tags:
  - attack.defense_evasion
  - attack.t1218.010
  - attack.execution
  - attack.t1117
  - car.2019-04-002
  - car.2019-04-003



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects various anomalies in relation to regsvr32.exe

<!--more-->


## Known false-positives

* Unknown



## References

* https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html


## Raw rule
```yaml
title: Regsvr32 Anomaly
id: 8e2b24c9-4add-46a0-b4bb-0057b4e6187d
status: experimental
description: Detects various anomalies in relation to regsvr32.exe
author: Florian Roth
date: 2019/01/16
modified: 2020/08/28
references:
    - https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html
tags:
    - attack.defense_evasion
    - attack.t1218.010      
    - attack.execution  # an old one  
    - attack.t1117      # an old one  
    - car.2019-04-002
    - car.2019-04-003

logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\regsvr32.exe'
        CommandLine: '*\Temp\\*'
    selection2:
        Image: '*\regsvr32.exe'
        ParentImage: '*\powershell.exe'
    selection3:
        Image: '*\regsvr32.exe'
        ParentImage: '*\cmd.exe'
    selection4:
        Image: '*\regsvr32.exe'
        CommandLine:
            - '*/i:http* scrobj.dll'
            - '*/i:ftp* scrobj.dll'
    selection5:
        Image: '*\wscript.exe'
        ParentImage: '*\regsvr32.exe'
    selection6:
        Image: '*\EXCEL.EXE'
        CommandLine: '*..\..\..\Windows\System32\regsvr32.exe *'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```