---
title: "Powershell Trigger Profiles by Add_Content"
aliases:
  - "/rule/05b3e303-faf0-4f4a-9b30-46cc13e69152"
ruleid: 05b3e303-faf0-4f4a-9b30-46cc13e69152

tags:
  - attack.privilege_escalation
  - attack.t1546.013



status: experimental





date: Wed, 18 Aug 2021 14:29:50 +0200


---

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.013/T1546.013.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_trigger_profiles.yml))
```yaml
title: Powershell Trigger Profiles by Add_Content
id: 05b3e303-faf0-4f4a-9b30-46cc13e69152
status: experimental
author: frack113
date: 2021/08/18
modified: 2021/10/16
description: Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.013/T1546.013.md
tags:
    - attack.privilege_escalation
    - attack.t1546.013
logsource:
    product: windows
    category: ps_script
    definition: EnableScriptBlockLogging must be set to enable
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Add-Content'
            - '$profile'
            - '-Value' 
        ScriptBlockText|contains: 
            - 'Start-Process'
            - '""'  #cleanup action
    condition: selection
falsepositives:
    - Unknown
level: medium
```
