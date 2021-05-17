---
title: "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)"
aliases:
  - "/rule/2afafd61-6aae-4df4-baed-139fa1f4c345"

tags:
  - attack.credential_access
  - attack.t1003.003
  - attack.t1003



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)

<!--more-->


## Known false-positives

* NTDS maintenance



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm


## Raw rule
```yaml
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
id: 2afafd61-6aae-4df4-baed-139fa1f4c345
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
status: experimental
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
author: Thomas Patzke
date: 2019/01/16
tags:
    - attack.credential_access
    - attack.t1003.003
    - attack.t1003      # an old one    
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\ntdsutil*'
    condition: selection
falsepositives:
    - NTDS maintenance
level: high

```
