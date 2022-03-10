---
title: "Using AppVLP To Circumvent ASR File Path Rule"
aliases:
  - "/rule/9c7e131a-0f2c-4ae0-9d43-b04f4e266d43"


tags:
  - attack.t1218
  - attack.defense_evasion
  - attack.execution



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Application Virtualization Utility is included with Microsoft Office. We are able to abuse "AppVLP" to execute shell commands.
Normally, this binary is used for Application Virtualization, but we can use it as an abuse binary to circumvent the ASR file path rule folder
or to mark a file as a system file.


<!--more-->


## Known false-positives

* unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_asr_bypass_via_appvlp_re.yml))
```yaml
title: Using AppVLP To Circumvent ASR File Path Rule
id: 9c7e131a-0f2c-4ae0-9d43-b04f4e266d43
status: experimental
description: |
  Application Virtualization Utility is included with Microsoft Office. We are able to abuse "AppVLP" to execute shell commands.
  Normally, this binary is used for Application Virtualization, but we can use it as an abuse binary to circumvent the ASR file path rule folder
  or to mark a file as a system file.
author: Sreeman
date: 2020/03/13
modified: 2022/03/08
logsource: 
    product: windows
    service: security
detection: 
    selection_1:
        CommandLine|contains: 'appvlp.exe'
    selection_2:
        CommandLine|contains:        
            - 'cmd.exe'
            - 'powershell.exe'
    selection_3:
        CommandLine|contains:        
            - '.sh'
            - '.exe'
            - '.dll'
            - '.bin'
            - '.bat'
            - '.cmd'
            - '.js'
            - '.msh'
            - '.reg'
            - '.scr'
            - '.ps'
            - '.vb'
            - '.jar'
            - '.pl'
            - '.inf'
    condition: all of selection_*
falsepositives: 
    - unknown
fields: 
    - ParentProcess
    - CommandLine
    - ParentCommandLine
level: medium
tags: 
    - attack.t1218
    - attack.defense_evasion
    - attack.execution

```
