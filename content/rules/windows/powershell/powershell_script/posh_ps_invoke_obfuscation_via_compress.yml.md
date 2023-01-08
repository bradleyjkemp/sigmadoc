---
title: "Invoke-Obfuscation COMPRESS OBFUSCATION"
aliases:
  - "/rule/20e5497e-331c-4cd5-8d36-935f6e2a9a07"
ruleid: 20e5497e-331c-4cd5-8d36-935f6e2a9a07

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via COMPRESS OBFUSCATION

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_compress.yml))
```yaml
title: Invoke-Obfuscation COMPRESS OBFUSCATION
id: 20e5497e-331c-4cd5-8d36-935f6e2a9a07
description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
status: experimental
author: Timur Zinniatullin, oscd.community
date: 2020/10/18
modified: 2022/03/08
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task 19)
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_4104:
        ScriptBlockText|contains|all: 
            - 'new-object'
            - 'text.encoding]::ascii'
        ScriptBlockText|contains: 
            - 'system.io.compression.deflatestream'
            - 'system.io.streamreader'
        ScriptBlockText|endswith: 'readtoend'
    condition: selection_4104
falsepositives:
    - unknown
level: medium
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001

```
