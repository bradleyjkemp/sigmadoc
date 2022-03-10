---
title: "Overwrite Deleted Data with Cipher"
aliases:
  - "/rule/4b046706-5789-4673-b111-66f25fe99534"


tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Sun, 26 Dec 2021 12:09:42 +0100


---

Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.
Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md#atomic-test-3---overwrite-deleted-data-on-c-drive


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_cipher.yml))
```yaml
title: Overwrite Deleted Data with Cipher
id: 4b046706-5789-4673-b111-66f25fe99534
status: experimental
description: |
  Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.
  Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives
author: frack113
date: 2021/12/26
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md#atomic-test-3---overwrite-deleted-data-on-c-drive
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \cipher.exe
        CommandLine|contains: ' /w:'
    condition: selection
falsepositives:
    - unknown
level: medium
tags:
    - attack.impact
    - attack.t1485
```
