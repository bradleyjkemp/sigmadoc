---
title: "Invoke-Obfuscation COMPRESS OBFUSCATION"
aliases:
  - "/rule/175997c5-803c-4b08-8bb0-70b099f47595"
ruleid: 175997c5-803c-4b08-8bb0-70b099f47595

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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_via_compress_services.yml))
```yaml
title: Invoke-Obfuscation COMPRESS OBFUSCATION
id: 175997c5-803c-4b08-8bb0-70b099f47595
description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
status: experimental
author: Timur Zinniatullin, oscd.community
date: 2020/10/18
modified: 2022/03/06
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task 19)
falsepositives:
    - unknown
level: medium
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains|all:
            - 'new-object'
            - 'text.encoding]::ascii'
            - 'readtoend'
        ImagePath|contains:    
            - ':system.io.compression.deflatestream'
            - 'system.io.streamreader'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001

```
