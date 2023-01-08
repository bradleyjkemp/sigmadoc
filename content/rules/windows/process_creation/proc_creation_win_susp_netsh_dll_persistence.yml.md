---
title: "Suspicious Netsh DLL Persistence"
aliases:
  - "/rule/56321594-9087-49d9-bf10-524fe8479452"
ruleid: 56321594-9087-49d9-bf10-524fe8479452

tags:
  - attack.privilege_escalation
  - attack.t1546.007
  - attack.s0108



status: test





date: Fri, 25 Oct 2019 15:38:47 +0400


---

Detects persitence via netsh helper

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.007/T1546.007.md
* https://attack.mitre.org/software/S0108/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_netsh_dll_persistence.yml))
```yaml
title: Suspicious Netsh DLL Persistence
id: 56321594-9087-49d9-bf10-524fe8479452
status: test
description: Detects persitence via netsh helper
author: Victor Sergeev, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.007/T1546.007.md
  - https://attack.mitre.org/software/S0108/
date: 2019/10/25
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all:
      - 'add'
      - 'helper'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Unknown
level: high
tags:
  - attack.privilege_escalation
  - attack.t1546.007
  - attack.s0108

```
