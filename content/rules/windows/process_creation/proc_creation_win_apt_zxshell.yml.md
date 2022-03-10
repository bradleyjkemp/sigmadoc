---
title: "ZxShell Malware"
aliases:
  - "/rule/f0b70adb-0075-43b0-9745-e82a1c608fcc"


tags:
  - attack.execution
  - attack.t1059.003
  - attack.defense_evasion
  - attack.t1218.011
  - attack.s0412
  - attack.g0001



status: test





date: Thu, 20 Jul 2017 12:36:24 -0600


---

Detects a ZxShell start by the called and well-known function name

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.hybrid-analysis.com/sample/5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16?environmentId=100


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_zxshell.yml))
```yaml
title: ZxShell Malware
id: f0b70adb-0075-43b0-9745-e82a1c608fcc
status: test
description: Detects a ZxShell start by the called and well-known function name
author: Florian Roth, oscd.community, Jonhnathan Ribeiro
references:
  - https://www.hybrid-analysis.com/sample/5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16?environmentId=100
date: 2017/07/20
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\rundll32.exe'
    CommandLine|contains:
      - 'zxFunction'
      - 'RemoteDiskXXXXX'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Unlikely
level: critical
tags:
  - attack.execution
  - attack.t1059.003
  - attack.defense_evasion
  - attack.t1218.011
  - attack.s0412
  - attack.g0001

```