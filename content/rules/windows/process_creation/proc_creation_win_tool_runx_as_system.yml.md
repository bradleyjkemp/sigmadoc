---
title: "RunXCmd Tool Execution As System"
aliases:
  - "/rule/93199800-b52a-4dec-b762-75212c196542"
ruleid: 93199800-b52a-4dec-b762-75212c196542

tags:
  - attack.execution
  - attack.t1569.002
  - attack.s0029



status: experimental





date: Mon, 24 Jan 2022 13:37:28 +0100


---

Detects the use of RunXCmd tool for command execution

<!--more-->


## Known false-positives

* Legitimate use by administrators



## References

* https://www.d7xtech.com/free-software/runx/
* https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_tool_runx_as_system.yml))
```yaml
title: RunXCmd Tool Execution As System
id: 93199800-b52a-4dec-b762-75212c196542
status: experimental
description: Detects the use of RunXCmd tool for command execution
author: Florian Roth
date: 2022/01/24
references:
    - https://www.d7xtech.com/free-software/runx/
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
        CommandLine|contains|all: 
            - ' /account=system '
            - '/exec='
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: high
```
