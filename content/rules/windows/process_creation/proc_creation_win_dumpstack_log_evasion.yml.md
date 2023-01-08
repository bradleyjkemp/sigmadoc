---
title: "DumpStack.log Defender Evasion"
aliases:
  - "/rule/4f647cfa-b598-4e12-ad69-c68dd16caef8"
ruleid: 4f647cfa-b598-4e12-ad69-c68dd16caef8

tags:
  - attack.defense_evasion



status: test





date: Fri, 7 Jan 2022 08:46:30 +0100


---

Detects the use of the filename DumpStack.log to evade Microsoft Defender

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/mrd0x/status/1479094189048713219


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_dumpstack_log_evasion.yml))
```yaml
title: DumpStack.log Defender Evasion
id: 4f647cfa-b598-4e12-ad69-c68dd16caef8
status: test
description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
references:
    - https://twitter.com/mrd0x/status/1479094189048713219
tags:
    - attack.defense_evasion
author: Florian Roth
date: 2022/01/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DumpStack.log'
    selection_download:
        CommandLine: ' -o DumpStack.log'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical

```
