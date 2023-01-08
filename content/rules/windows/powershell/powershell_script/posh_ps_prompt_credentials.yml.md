---
title: "PowerShell Credential Prompt"
aliases:
  - "/rule/ca8b77a9-d499-4095-b793-5d5f330d450e"
ruleid: ca8b77a9-d499-4095-b793-5d5f330d450e

tags:
  - attack.credential_access
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sun, 9 Apr 2017 10:22:04 +0200


---

Detects PowerShell calling a credential prompt

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/JohnLaTwC/status/850381440629981184
* https://t.co/ezOTGy1a1G


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_prompt_credentials.yml))
```yaml
title: PowerShell Credential Prompt
id: ca8b77a9-d499-4095-b793-5d5f330d450e
status: experimental
description: Detects PowerShell calling a credential prompt
references:
    - https://twitter.com/JohnLaTwC/status/850381440629981184
    - https://t.co/ezOTGy1a1G
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1059.001
author: John Lambert (idea), Florian Roth (rule)
date: 2017/04/09
modified: 2021/10/16
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: 'PromptForCredential'
    condition: selection
falsepositives: 
    - Unknown
level: high

```
