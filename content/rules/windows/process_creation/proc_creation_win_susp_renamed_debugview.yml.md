---
title: "Renamed SysInternals Debug View"
aliases:
  - "/rule/cd764533-2e07-40d6-a718-cfeec7f2da7f"


tags:
  - attack.resource_development
  - attack.t1588.002



status: test





date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects suspicious renamed SysInternals DebugView execution

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.epicturla.com/blog/sysinturla


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_renamed_debugview.yml))
```yaml
title: Renamed SysInternals Debug View
id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: test
description: Detects suspicious renamed SysInternals DebugView execution
author: Florian Roth
references:
  - https://www.epicturla.com/blog/sysinturla
date: 2020/05/28
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Product:
      - 'Sysinternals DebugView'
      - 'Sysinternals Debugview'
  filter:
    OriginalFileName: 'Dbgview.exe'
    Image|endswith: '\Dbgview.exe'
  condition: selection and not filter
falsepositives:
  - Unknown
level: high
tags:
  - attack.resource_development
  - attack.t1588.002

```
