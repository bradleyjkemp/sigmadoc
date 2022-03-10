---
title: "NSudo Tool Execution As System"
aliases:
  - "/rule/771d1eb5-9587-4568-95fb-9ec44153a012"


tags:
  - attack.execution
  - attack.t1569.002
  - attack.s0029



status: experimental





date: Mon, 24 Jan 2022 13:37:28 +0100


---

Detects the use of NSudo tool for command execution

<!--more-->


## Known false-positives

* Legitimate use by administrators



## References

* https://nsudo.m2team.org/en-us/
* https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_tool_nsudo_as_system.yml))
```yaml
title: NSudo Tool Execution As System
id: 771d1eb5-9587-4568-95fb-9ec44153a012
status: experimental
description: Detects the use of NSudo tool for command execution
author: Florian Roth
date: 2022/01/24
references:
    - https://nsudo.m2team.org/en-us/
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\NSudo.exe'
        CommandLine|contains: ' -U:S '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: high
```
