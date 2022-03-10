---
title: "Binary Padding"
aliases:
  - "/rule/95361ce5-c891-4b0a-87ca-e24607884a96"


tags:
  - attack.defense_evasion
  - attack.t1027.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.

<!--more-->


## Known false-positives

* Legitimate script work



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_binary_padding.yml))
```yaml
title: 'Binary Padding'
id: 95361ce5-c891-4b0a-87ca-e24607884a96
status: test
description: 'Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.'
author: 'Igor Fits, Mikhail Larin, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection1:
    Image|endswith:
      - '/truncate'
    CommandLine|contains:
      - '-s'
  selection2:
    Image|endswith:
      - '/dd'
    CommandLine|contains:
      - 'if='
  filter:
    CommandLine|contains: 'of='
  condition: selection1 or (selection2 and not filter)
falsepositives:
  - 'Legitimate script work'
level: high
tags:
  - attack.defense_evasion
  - attack.t1027.001

```
