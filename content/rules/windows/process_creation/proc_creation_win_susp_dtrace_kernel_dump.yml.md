---
title: "Suspicious Kernel Dump Using Dtrace"
aliases:
  - "/rule/7124aebe-4cd7-4ccb-8df0-6d6b93c96795"
ruleid: 7124aebe-4cd7-4ccb-8df0-6d6b93c96795



status: experimental





date: Tue, 28 Dec 2021 10:01:11 +0100


---

Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/0gtweet/status/1474899714290208777?s=12
* https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_dtrace_kernel_dump.yml))
```yaml
title: Suspicious Kernel Dump Using Dtrace
id: 7124aebe-4cd7-4ccb-8df0-6d6b93c96795
status: experimental
description: Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1
author: Florian Roth
date: 2021/12/28
references:
    - https://twitter.com/0gtweet/status/1474899714290208777?s=12
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace
logsource:
    product: windows
    category: process_creation
detection:
    selection_plain:
        Image|endswith: '\dtrace.exe'
        CommandLine|contains: 'lkd(0)'
    selection_obfuscated:
        CommandLine|contains|all:
            - 'syscall:::return'
            - 'lkd('
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```
