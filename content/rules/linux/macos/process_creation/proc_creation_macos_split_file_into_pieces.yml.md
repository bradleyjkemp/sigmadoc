---
title: "Split A File Into Pieces"
aliases:
  - "/rule/7f2bb9d5-6395-4de5-969c-70c11fbe6b12"
ruleid: 7f2bb9d5-6395-4de5-969c-70c11fbe6b12

tags:
  - attack.exfiltration
  - attack.t1030



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detection use of the command "split" to split files into parts and possible transfer.

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1030/T1030.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml))
```yaml
title: 'Split A File Into Pieces'
id: 7f2bb9d5-6395-4de5-969c-70c11fbe6b12
status: test
description: 'Detection use of the command "split" to split files into parts and possible transfer.'
author: 'Igor Fits, Mikhail Larin, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1030/T1030.md
date: 2020/10/15
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: '/split'
  condition: selection
falsepositives:
  - 'Legitimate administrative activity'
level: low
tags:
  - attack.exfiltration
  - attack.t1030

```
