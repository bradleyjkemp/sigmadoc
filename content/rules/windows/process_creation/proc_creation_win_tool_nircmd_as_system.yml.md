---
title: "NirCmd Tool Execution As LOCAL SYSTEM"
aliases:
  - "/rule/d9047477-0359-48c9-b8c7-792cedcdc9c4"
ruleid: d9047477-0359-48c9-b8c7-792cedcdc9c4

tags:
  - attack.execution
  - attack.t1569.002
  - attack.s0029



status: experimental





date: Mon, 24 Jan 2022 13:37:28 +0100


---

Detects the use of NirCmd tool for command execution as SYSTEM user

<!--more-->


## Known false-positives

* Legitimate use by administrators



## References

* https://www.nirsoft.net/utils/nircmd.html
* https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
* https://www.nirsoft.net/utils/nircmd2.html#using


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_tool_nircmd_as_system.yml))
```yaml
title: NirCmd Tool Execution As LOCAL SYSTEM
id: d9047477-0359-48c9-b8c7-792cedcdc9c4
status: experimental
description: Detects the use of NirCmd tool for command execution as SYSTEM user
author: 'Florian Roth, Nasreddine Bencherchali @nas_bench'
date: 2022/01/24
references:
    - https://www.nirsoft.net/utils/nircmd.html
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
    - https://www.nirsoft.net/utils/nircmd2.html#using
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ' runassystem '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: high

```
