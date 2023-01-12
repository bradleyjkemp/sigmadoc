---
title: "Powershell Keylogging"
aliases:
  - "/rule/34f90d3c-c297-49e9-b26d-911b05a4866c"
ruleid: 34f90d3c-c297-49e9-b26d-911b05a4866c

tags:
  - attack.collection
  - attack.t1056.001



status: experimental





date: Fri, 30 Jul 2021 08:28:19 +0200


---

Adversaries may log user keystrokes to intercept credentials as the user types them.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/src/Get-Keystrokes.ps1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_keylogging.yml))
```yaml
title: Powershell Keylogging
id: 34f90d3c-c297-49e9-b26d-911b05a4866c
status: experimental
author: frack113
date: 2021/07/30
modified: 2021/10/16
description: Adversaries may log user keystrokes to intercept credentials as the user types them.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/src/Get-Keystrokes.ps1
tags:
    - attack.collection
    - attack.t1056.001
logsource:
    product: windows
    category: ps_script
    definition: EnableScriptBlockLogging must be set to enable
detection:
    selection_basic:
        ScriptBlockText|contains: 'Get-Keystrokes'    
    selection_high: # want to run in background and keyboard
        ScriptBlockText|contains|all:
            - 'Get-ProcAddress user32.dll GetAsyncKeyState'
            - 'Get-ProcAddress user32.dll GetForegroundWindow'
    condition: selection_basic or selection_high
falsepositives:
    - Unknown
level: medium

```