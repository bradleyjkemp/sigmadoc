---
title: "File Created with System Process Name"
aliases:
  - "/rule/d5866ddf-ce8f-4aea-b28e-d96485a20d3d"

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.005



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects the creation of a executable with a system process name in a suspicious folder

<!--more-->


## Known false-positives

* System processes copied outside the default folder




## Raw rule
```yaml
title: File Created with System Process Name
id: d5866ddf-ce8f-4aea-b28e-d96485a20d3d
status: experimental
description: Detects the creation of a executable with a system process name in a suspicious folder
author: Sander Wiebing
date: 2020/05/26
modified: 2020/08/23
tags:
    - attack.defense_evasion
    - attack.t1036          # an old one
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename:
            - '*\svchost.exe'
            - '*\rundll32.exe'
            - '*\services.exe'
            - '*\powershell.exe'
            - '*\regsvr32.exe'
            - '*\spoolsv.exe'
            - '*\lsass.exe'
            - '*\smss.exe'
            - '*\csrss.exe'
            - '*\conhost.exe'
            - '*\wininit.exe'
            - '*\lsm.exe'
            - '*\winlogon.exe'
            - '*\explorer.exe'
            - '*\taskhost.exe'
            - '*\Taskmgr.exe'
            - '*\taskmgr.exe'
            - '*\sihost.exe'
            - '*\RuntimeBroker.exe'
            - '*\runtimebroker.exe'
            - '*\smartscreen.exe'
            - '*\dllhost.exe'
            - '*\audiodg.exe'
            - '*\wlanext.exe'
    filter:
        TargetFilename:
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\system32\\*'
            - 'C:\Windows\SysWow64\\*'
            - 'C:\Windows\SysWOW64\\*'
            - 'C:\Windows\winsxs\\*'
            - 'C:\Windows\WinSxS\\*'
            - '\SystemRoot\System32\\*'
    condition: selection and not filter
fields:
    - Image
falsepositives:
    - System processes copied outside the default folder
level: high

```