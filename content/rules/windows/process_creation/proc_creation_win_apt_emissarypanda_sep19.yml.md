---
title: "Emissary Panda Malware SLLauncher"
aliases:
  - "/rule/9aa01d62-7667-4d3b-acb8-8cb5103e2014"


tags:
  - attack.defense_evasion
  - attack.t1574.002



status: test





date: Tue, 3 Sep 2019 15:35:23 +0200


---

Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27

<!--more-->


## Known false-positives

* Unknown



## References

* https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965
* https://twitter.com/cyb3rops/status/1168863899531132929


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_emissarypanda_sep19.yml))
```yaml
title: Emissary Panda Malware SLLauncher
id: 9aa01d62-7667-4d3b-acb8-8cb5103e2014
status: test
description: Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27
author: Florian Roth
references:
  - https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965
  - https://twitter.com/cyb3rops/status/1168863899531132929
date: 2018/09/03
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\sllauncher.exe'
    Image|endswith: '\svchost.exe'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.t1574.002

```
