---
title: "Explorer NOUACCHECK Flag"
aliases:
  - "/rule/534f2ef7-e8a2-4433-816d-c91bccde289b"


tags:
  - attack.defense_evasion
  - attack.t1548.002



status: test





date: Wed, 23 Feb 2022 15:47:44 +0100


---

Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks

<!--more-->


## Known false-positives

* Unknown how many legitimate software products use that method



## References

* https://twitter.com/ORCA6665/status/1496478087244095491


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_explorer_nouaccheck.yml))
```yaml
title: Explorer NOUACCHECK Flag
id: 534f2ef7-e8a2-4433-816d-c91bccde289b
status: test
description: Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks
author: Florian Roth
references:
  - https://twitter.com/ORCA6665/status/1496478087244095491
date: 2022/02/23
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\explorer.exe'
    CommandLine|contains: '/NOUACCHECK'
  condition: selection
falsepositives:
  - Unknown how many legitimate software products use that method
level: high
tags:
  - attack.defense_evasion
  - attack.t1548.002

```
