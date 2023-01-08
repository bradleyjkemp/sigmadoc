---
title: "Powershell Execute Batch Script"
aliases:
  - "/rule/b5522a23-82da-44e5-9c8b-e10ed8955f88"
ruleid: b5522a23-82da-44e5-9c8b-e10ed8955f88

tags:
  - attack.execution
  - attack.t1059.003



status: experimental





date: Sun, 2 Jan 2022 10:36:52 +0100


---

Adversaries may abuse the Windows command shell for execution.
The Windows command shell ([cmd](https://attack.mitre.org/software/S0106)) is the primary command prompt on Windows systems.
The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands.
Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops.
Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple system


<!--more-->


## Known false-positives

* legitim administration script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md#atomic-test-1---create-and-execute-batch-script


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_execute_batch_script.yml))
```yaml
title: Powershell Execute Batch Script
id: b5522a23-82da-44e5-9c8b-e10ed8955f88
description: |
  Adversaries may abuse the Windows command shell for execution.
  The Windows command shell ([cmd](https://attack.mitre.org/software/S0106)) is the primary command prompt on Windows systems.
  The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands.
  Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops.
  Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md#atomic-test-1---create-and-execute-batch-script
status: experimental
author: frack113
date: 2022/01/02
logsource:
    product: windows
    category: ps_script
detection:
    selection_start:
        ScriptBlockText|contains: Start-Process
    selection_batch:
        ScriptBlockText|contains: 
            - '.cmd' 
            - '.bat'
    condition: all of selection_*
falsepositives:
    - legitim administration script
level: medium
tags:
    - attack.execution
    - attack.t1059.003
```
