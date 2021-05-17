---
title: "Renamed SysInternals Debug View"
aliases:
  - "/rule/cd764533-2e07-40d6-a718-cfeec7f2da7f"



status: experimental



level: high



date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects suspicious renamed SysInternals DebugView execution

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.epicturla.com/blog/sysinturla


## Raw rule
```yaml
title: Renamed SysInternals Debug View
id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: experimental
description: Detects suspicious renamed SysInternals DebugView execution
references:
    - https://www.epicturla.com/blog/sysinturla
author: Florian Roth
date: 2020/05/28
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 
            - 'Sysinternals DebugView'
            - 'Sysinternals Debugview'
    filter:
        OriginalFilename: 'Dbgview.exe'
        Image|endswith: '\Dbgview.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
