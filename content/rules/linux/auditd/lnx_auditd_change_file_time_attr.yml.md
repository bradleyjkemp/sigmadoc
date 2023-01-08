---
title: "File Time Attribute Change"
aliases:
  - "/rule/b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b"
ruleid: b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b

tags:
  - attack.defense_evasion
  - attack.t1070.006



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detect file time attribute change to hide new or changes to existing files.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_change_file_time_attr.yml))
```yaml
title: 'File Time Attribute Change'
id: b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b
status: test
description: 'Detect file time attribute change to hide new or changes to existing files.'
author: 'Igor Fits, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md
date: 2020/10/15
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  execve:
    type: 'EXECVE'
  touch:
    - 'touch'
  selection2:
    - '-t'
    - '-acmr'
    - '-d'
    - '-r'
  condition: execve and touch and selection2
falsepositives:
  - 'Unknown'
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.006

```
