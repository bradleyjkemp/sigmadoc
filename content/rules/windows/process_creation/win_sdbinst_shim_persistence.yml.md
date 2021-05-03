---
title: "Possible Shim Database Persistence via sdbinst.exe"
aliases:
  - "/rule/517490a7-115a-48c6-8862-1a481504d5a8"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.011
  - attack.t1138



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html


## Raw rule
```yaml
title: Possible Shim Database Persistence via sdbinst.exe
id: 517490a7-115a-48c6-8862-1a481504d5a8
status: experimental
description: Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.
references:
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.011
    - attack.t1138 # an old one
author: Markus Neis
date: 2019/01/16
modified: 2020/09/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\sdbinst.exe'
        CommandLine:
            - '*.sdb*'
    condition: selection
falsepositives:
    - Unknown
level: high

```
