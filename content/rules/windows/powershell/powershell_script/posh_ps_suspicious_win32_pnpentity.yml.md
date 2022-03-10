---
title: "Powershell Suspicious Win32_PnPEntity"
aliases:
  - "/rule/b26647de-4feb-4283-af6b-6117661283c5"


tags:
  - attack.discovery
  - attack.t1120



status: experimental





date: Mon, 23 Aug 2021 13:17:35 +0200


---

Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.

<!--more-->


## Known false-positives

* admin script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_win32_pnpentity.yml))
```yaml
title: Powershell Suspicious Win32_PnPEntity  
id: b26647de-4feb-4283-af6b-6117661283c5
status: experimental
author: frack113
date: 2021/08/23
modified: 2021/10/16
description: Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md
tags:
    - attack.discovery
    - attack.t1120
logsource:
    product: windows
    category: ps_script
    definition: EnableScriptBlockLogging must be set to enable
detection:
    selection:
        ScriptBlockText|contains: Win32_PnPEntity
    condition: selection
falsepositives:
    - admin script
level: low
```
