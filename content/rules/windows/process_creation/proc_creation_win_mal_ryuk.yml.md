---
title: "Ryuk Ransomware"
aliases:
  - "/rule/0acaad27-9f02-4136-a243-c357202edd74"


tags:
  - attack.execution
  - attack.t1204



status: test





date: Tue, 6 Aug 2019 10:33:46 +0200


---

Detects Ryuk Ransomware command lines

<!--more-->


## Known false-positives

* Unlikely



## References

* https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mal_ryuk.yml))
```yaml
title: Ryuk Ransomware
id: 0acaad27-9f02-4136-a243-c357202edd74
status: test
description: Detects Ryuk Ransomware command lines
author: Vasiliy Burov
references:
  - https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/
date: 2019/08/06
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains|all:
      - 'stop'
    CommandLine|contains:
      - 'samss'
      - 'audioendpointbuilder'
      - 'unistoresvc_?????'
  condition: selection
falsepositives:
  - Unlikely
level: critical
tags:
  - attack.execution
  - attack.t1204

```
