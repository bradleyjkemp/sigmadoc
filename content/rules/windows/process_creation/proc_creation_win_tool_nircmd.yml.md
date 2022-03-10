---
title: "NirCmd Tool Execution"
aliases:
  - "/rule/4e2ed651-1906-4a59-a78a-18220fca1b22"


tags:
  - attack.execution
  - attack.t1569.002
  - attack.s0029



status: experimental





date: Mon, 24 Jan 2022 13:37:28 +0100


---

Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity

<!--more-->


## Known false-positives

* Legitimate use by administrators



## References

* https://www.nirsoft.net/utils/nircmd.html
* https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
* https://www.nirsoft.net/utils/nircmd2.html#using


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_tool_nircmd.yml))
```yaml
title: NirCmd Tool Execution
id: 4e2ed651-1906-4a59-a78a-18220fca1b22
status: experimental
description: Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity
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
        Image|endswith:
            - '\nircmd.exe'
            - '\nircmdc.exe'
    selection_params:
        CommandLine|contains:
            - ' execmd '
            - ' exec2 '
    selection_commands:
        CommandLine|contains:
            - ' copy '
            - ' del '
    condition: selection or ( selection_params and selection_commands )
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: medium

```
