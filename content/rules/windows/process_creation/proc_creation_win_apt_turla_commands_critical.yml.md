---
title: "Turla Group Lateral Movement"
aliases:
  - "/rule/c601f20d-570a-4cde-a7d6-e17f99cb8e7f"


tags:
  - attack.g0010
  - attack.execution
  - attack.t1059
  - attack.lateral_movement
  - attack.t1021.002
  - attack.discovery
  - attack.t1083
  - attack.t1135



status: experimental





date: Wed, 8 Nov 2017 00:33:17 +0100


---

Detects automated lateral movement by Turla group

<!--more-->


## Known false-positives

* Unknown



## References

* https://securelist.com/the-epic-turla-operation/65545/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_turla_commands_critical.yml))
```yaml
title: Turla Group Lateral Movement
id: c601f20d-570a-4cde-a7d6-e17f99cb8e7f
status: experimental
description: Detects automated lateral movement by Turla group
references:
    - https://securelist.com/the-epic-turla-operation/65545/
tags:
    - attack.g0010
    - attack.execution
    - attack.t1059
    - attack.lateral_movement
    - attack.t1021.002
    - attack.discovery
    - attack.t1083
    - attack.t1135
author: Markus Neis
date: 2017/11/07
modified: 2021/09/19
logsource:
    category: process_creation
    product: windows
detection:
   selection:
      CommandLine:
         - 'net use \\%DomainController%\C$ "P@ssw0rd" *'
         - 'dir c:\\*.doc* /s'
         - 'dir %TEMP%\\*.exe'
   condition: selection
level: critical
falsepositives:
   - Unknown
```
