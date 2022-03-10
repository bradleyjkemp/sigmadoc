---
title: "Cmd Stream Redirection"
aliases:
  - "/rule/70e68156-6571-427b-a6e9-4476a173a9b6"


tags:
  - attack.defense_evasion
  - attack.t1564.004



status: experimental





date: Fri, 4 Feb 2022 10:49:50 +0100


---

Detects the redirection of an output stream of / within a Windows command line session

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md#atomic-test-3---create-ads-command-prompt


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_redirect_to_stream.yml))
```yaml
title: Cmd Stream Redirection
id: 70e68156-6571-427b-a6e9-4476a173a9b6
status: experimental
description: Detects the redirection of an output stream of / within a Windows command line session
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md#atomic-test-3---create-ads-command-prompt
date: 2022/02/04
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \cmd.exe
        CommandLine|contains: '>*:'
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.defense_evasion
    - attack.t1564.004

```
