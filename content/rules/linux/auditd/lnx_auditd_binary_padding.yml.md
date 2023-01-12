---
title: "Binary Padding"
aliases:
  - "/rule/c52a914f-3d8b-4b2a-bb75-b3991e75f8ba"
ruleid: c52a914f-3d8b-4b2a-bb75-b3991e75f8ba

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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_binary_padding.yml))
```yaml
title: 'Binary Padding'
id: c52a914f-3d8b-4b2a-bb75-b3991e75f8ba
status: test
description: 'Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.'
author: 'Igor Fits, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md
date: 2020/10/13
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  execve:
    type: 'EXECVE'
  truncate:
    - 'truncate'
    - '-s'
  dd:
    - 'dd'
    - 'if='
  filter:
    - 'of='
  condition: execve and (all of truncate or (all of dd and not filter))
falsepositives:
  - 'Legitimate script work'
level: high
tags:
  - attack.defense_evasion
  - attack.t1027.001

```