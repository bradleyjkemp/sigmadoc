---
title: "Load Undocumented Autoelevated COM Interface"
aliases:
  - "/rule/fb3722e4-1a06-46b6-b772-253e2e7db933"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

COM interface (EditionUpgradeManager) that is not used by standard executables.

<!--more-->


## Known false-positives

* unknown



## References

* https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/
* https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_load_undocumented_autoelevated_com_interface.yml))
```yaml
title: Load Undocumented Autoelevated COM Interface
id: fb3722e4-1a06-46b6-b772-253e2e7db933
status: test
description: COM interface (EditionUpgradeManager) that is not used by standard executables.
author: oscd.community, Dmitry Uchakin
references:
  - https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/
  - https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_access
  product: windows
detection:
  selection:
    CallTrace|contains: 'editionupgrademanagerobj.dll'
  condition: selection
fields:
  - ComputerName
  - User
  - SourceImage
  - TargetImage
  - CallTrace
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002

```
