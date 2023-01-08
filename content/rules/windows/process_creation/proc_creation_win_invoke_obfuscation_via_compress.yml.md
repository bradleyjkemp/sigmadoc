---
title: "Invoke-Obfuscation COMPRESS OBFUSCATION"
aliases:
  - "/rule/7eedcc9d-9fdb-4d94-9c54-474e8affc0c7"
ruleid: 7eedcc9d-9fdb-4d94-9c54-474e8affc0c7

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via COMPRESS OBFUSCATION

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_compress.yml))
```yaml
title: Invoke-Obfuscation COMPRESS OBFUSCATION
id: 7eedcc9d-9fdb-4d94-9c54-474e8affc0c7
status: test
description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
author: Timur Zinniatullin, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009   #(Task 19)
date: 2020/10/18
modified: 2022/03/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'new-object'
      - 'text.encoding]::ascii'
    CommandLine|contains:
      - 'system.io.compression.deflatestream'
      - 'system.io.streamreader'
    CommandLine|endswith: 'readtoend'
  condition: selection
falsepositives:
  - unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001

```
