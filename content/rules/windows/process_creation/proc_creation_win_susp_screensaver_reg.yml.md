---
title: "Suspicious ScreenSave Change by Reg.exe"
aliases:
  - "/rule/0fc35fc3-efe6-4898-8a37-0b233339524f"
ruleid: 0fc35fc3-efe6-4898-8a37-0b233339524f

tags:
  - attack.privilege_escalation
  - attack.t1546.002



status: experimental





date: Thu, 19 Aug 2021 13:55:09 +0200


---

Adversaries may establish persistence by executing malicious content triggered by user inactivity.
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension


<!--more-->


## Known false-positives

* GPO



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md
* https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_screensaver_reg.yml))
```yaml
title: Suspicious ScreenSave Change by Reg.exe  
id: 0fc35fc3-efe6-4898-8a37-0b233339524f
status: experimental
author: frack113
date: 2021/08/19
description: |
 Adversaries may establish persistence by executing malicious content triggered by user inactivity.
 Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md
    - https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf
tags:
    - attack.privilege_escalation
    - attack.t1546.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg:
        Image|endswith: reg.exe
        CommandLine|contains:
            - 'HKEY_CURRENT_USER\Control Panel\Desktop'
            - 'HKCU\Control Panel\Desktop'
    selection_option_1: # /force Active ScreenSaveActive 
        CommandLine|contains|all:
            - '/v ScreenSaveActive'
            - '/t REG_SZ'
            - '/d 1'
            - '/f'
    selection_option_2: # /force  set ScreenSaveTimeout 
        CommandLine|contains|all:
            - '/v ScreenSaveTimeout'
            - '/t REG_SZ'
            - '/d '
            - '/f'
    selection_option_3: # /force set ScreenSaverIsSecure 
        CommandLine|contains|all:
            - '/v ScreenSaverIsSecure'
            - '/t REG_SZ'
            - '/d 0'
            - '/f'
    selection_option_4: # /force set a .scr
        CommandLine|contains|all:
            - '/v SCRNSAVE.EXE'
            - '/t REG_SZ'
            - '/d '
            - '.scr'
            - '/f'
    condition: selection_reg and 1 of selection_option_*
falsepositives:
    - GPO 
level: medium
```