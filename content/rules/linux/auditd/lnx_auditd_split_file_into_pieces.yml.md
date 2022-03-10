---
title: "Split A File Into Pieces"
aliases:
  - "/rule/2dad0cba-c62a-4a4f-949f-5f6ecd619769"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_split_file_into_pieces.yml))
```yaml
title: 'Split A File Into Pieces'
id: 2dad0cba-c62a-4a4f-949f-5f6ecd619769
status: test
description: 'Detection use of the command "split" to split files into parts and possible transfer.'
author: 'Igor Fits, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1030/T1030.md
date: 2020/10/15
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: 'SYSCALL'
    comm: 'split'
  condition: selection
falsepositives:
  - 'Legitimate administrative activity'
level: low
tags:
  - attack.exfiltration
  - attack.t1030

```
