---
title: "Microsoft Workflow Compiler"
aliases:
  - "/rule/419dbf2b-8a9b-4bea-bf99-7544b050ec8d"

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1127



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.

<!--more-->


## Known false-positives

* Legitimate MWC use (unlikely in modern enterprise environments)



## References

* https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb


## Raw rule
```yaml
title: Microsoft Workflow Compiler
id: 419dbf2b-8a9b-4bea-bf99-7544b050ec8d
status: experimental
description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1127
author: Nik Seetharaman
date: 2019/01/16
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Microsoft.Workflow.Compiler.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: high

```
