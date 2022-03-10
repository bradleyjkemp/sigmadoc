---
title: "Regsvr32 Anomaly"
aliases:
  - "/rule/8e2b24c9-4add-46a0-b4bb-0057b4e6187d"


tags:
  - attack.defense_evasion
  - attack.t1218.010
  - car.2019-04-002
  - car.2019-04-003



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects various anomalies in relation to regsvr32.exe

<!--more-->


## Known false-positives

* Unknown



## References

* https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html
* https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_regsvr32_anomalies.yml))
```yaml
title: Regsvr32 Anomaly
id: 8e2b24c9-4add-46a0-b4bb-0057b4e6187d
status: experimental
description: Detects various anomalies in relation to regsvr32.exe
author: Florian Roth, oscd.community
date: 2019/01/16
modified: 2021/07/18
references:
    - https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html
    - https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/
tags:
    - attack.defense_evasion
    - attack.t1218.010      
    - car.2019-04-002
    - car.2019-04-003
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains: '\Temp\'
    selection2:
        Image|endswith: '\regsvr32.exe'
        ParentImage|endswith: '\powershell.exe'
    selection3:
        Image|endswith: '\regsvr32.exe'
        ParentImage|endswith: '\cmd.exe'
    selection4:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|all: 
            - '/i:'
        CommandLine|contains:
            - 'http'
            - 'ftp'
        CommandLine|endswith: 'scrobj.dll'
    selection5:
        Image|endswith: '\wscript.exe'
        ParentImage|endswith: '\regsvr32.exe'
    selection6:
        Image|endswith: '\EXCEL.EXE'
        CommandLine|contains: '..\..\..\Windows\System32\regsvr32.exe '
    selection7:
        ParentImage|endswith: '\mshta.exe'
        Image|endswith: '\regsvr32.exe'
    selection8:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains: 
            - '\AppData\Local'
            - 'C:\Users\Public'
    condition: 1 of selection*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```