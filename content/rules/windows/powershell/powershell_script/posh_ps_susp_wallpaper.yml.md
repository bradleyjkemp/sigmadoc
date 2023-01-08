---
title: "Replace Desktop Wallpaper by Powershell"
aliases:
  - "/rule/c5ac6a1e-9407-45f5-a0ce-ca9a0806a287"
ruleid: c5ac6a1e-9407-45f5-a0ce-ca9a0806a287

tags:
  - attack.impact
  - attack.t1491.001



status: experimental





date: Sun, 26 Dec 2021 12:09:42 +0100


---

An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users.
This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_susp_wallpaper.yml))
```yaml
title: Replace Desktop Wallpaper by Powershell
id: c5ac6a1e-9407-45f5-a0ce-ca9a0806a287
status: experimental
author: frack113
date: 2021/12/26
description: |
    An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users.
    This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_1:
        ScriptBlockText|contains|all:
            - 'Get-ItemProperty'
            - 'Registry::'
            - 'HKEY_CURRENT_USER\Control Panel\Desktop\' 
            - 'WallPaper'
    selection_2:
        ScriptBlockText|contains: SystemParametersInfo(20,0,*,3)
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: low
tags:
    - attack.impact
    - attack.t1491.001


```
