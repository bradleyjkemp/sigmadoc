---
title: "Chafer Activity"
aliases:
  - "/rule/53ba33fd-3a50-4468-a5ef-c583635cfa92"

tags:
  - attack.persistence
  - attack.g0049
  - attack.t1053
  - attack.t1053.005
  - attack.s0111
  - attack.t1050
  - attack.t1543.003
  - attack.defense_evasion
  - attack.t1112
  - attack.command_and_control
  - attack.t1071
  - attack.t1071.004





level: critical



date: Fri, 23 Mar 2018 08:59:00 +0100


---

Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018

<!--more-->


## Known false-positives

* Unknown



## References

* https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/


## Raw rule
```yaml
action: global
title: Chafer Activity
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
description: Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018
references:
    - https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
tags:
    - attack.persistence
    - attack.g0049
    - attack.t1053 # an old one
    - attack.t1053.005
    - attack.s0111
    - attack.t1050 # an old one
    - attack.t1543.003
    - attack.defense_evasion
    - attack.t1112
    - attack.command_and_control
    - attack.t1071 # an old one
    - attack.t1071.004
date: 2018/03/23
modified: 2020/08/26
author: Florian Roth, Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: critical
---
logsource:
    product: windows
    service: system
detection:
    selection_service:
        EventID: 7045
        ServiceName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
---
logsource:
    product: windows
    service: security
detection:
    selection_service:
        EventID: 4698
        TaskName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
---
logsource:
   product: windows
   service: sysmon
detection:
    selection_reg1:
        EventID: 13 
        TargetObject: 
            - '*SOFTWARE\Microsoft\Windows\CurrentVersion\UMe'
            - '*SOFTWARE\Microsoft\Windows\CurrentVersion\UT'
        EventType: 'SetValue'
    selection_reg2:
        EventID: 13 
        TargetObject: '*\Control\SecurityProviders\WDigest\UseLogonCredential'
        EventType: 'SetValue'
        Details: 'DWORD (0x00000001)'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process1:
        CommandLine: 
            - '*\Service.exe i'
            - '*\Service.exe u'
            - '*\microsoft\Taskbar\autoit3.exe'
            - 'C:\wsc.exe*'
    selection_process2:
        Image: '*\Windows\Temp\DB\\*.exe'
    selection_process3:
        CommandLine: '*\nslookup.exe -q=TXT*'
        ParentImage: '*\Autoit*'

```
