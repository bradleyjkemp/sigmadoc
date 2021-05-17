---
title: "Sticky Key Like Backdoor Usage"
aliases:
  - "/rule/baca5663-583c-45f9-b5dc-ea96a22ce542"

tags:
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1015
  - attack.t1546.008
  - car.2014-11-003
  - car.2014-11-008





level: critical



date: Thu, 15 Mar 2018 19:53:34 +0100


---

Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen

<!--more-->


## Known false-positives

* Unlikely



## References

* https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/


## Raw rule
```yaml
action: global
title: Sticky Key Like Backdoor Usage
id: baca5663-583c-45f9-b5dc-ea96a22ce542
description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login
    screen
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1015 # an old one
    - attack.t1546.008
    - car.2014-11-003
    - car.2014-11-008
author: Florian Roth, @twjackomo
date: 2018/03/15
modified: 2020/09/06    
falsepositives:
    - Unlikely
level: critical
---
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:     
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger'
        EventType: 'SetValue'
    condition: 1 of them
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        ParentImage:
            - '*\winlogon.exe'
        CommandLine:
            - '*cmd.exe sethc.exe *'
            - '*cmd.exe utilman.exe *'
            - '*cmd.exe osk.exe *'
            - '*cmd.exe Magnify.exe *'
            - '*cmd.exe Narrator.exe *'
            - '*cmd.exe DisplaySwitch.exe *'
    condition: 1 of them

```
