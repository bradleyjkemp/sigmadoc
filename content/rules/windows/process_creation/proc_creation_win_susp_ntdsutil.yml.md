---
title: "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)"
aliases:
  - "/rule/2afafd61-6aae-4df4-baed-139fa1f4c345"


tags:
  - attack.credential_access
  - attack.t1003.003



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)

<!--more-->


## Known false-positives

* NTDS maintenance



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ntdsutil.yml))
```yaml
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
id: 2afafd61-6aae-4df4-baed-139fa1f4c345
status: test
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
author: Thomas Patzke
references:
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
date: 2019/01/16
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\ntdsutil.exe'
  condition: selection
falsepositives:
  - NTDS maintenance
level: medium
tags:
  - attack.credential_access
  - attack.t1003.003

```
