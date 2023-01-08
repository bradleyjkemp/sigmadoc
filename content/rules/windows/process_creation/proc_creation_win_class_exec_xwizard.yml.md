---
title: "Custom Class Execution via Xwizard"
aliases:
  - "/rule/53d4bb30-3f36-4e8a-b078-69d36c4a79ff"
ruleid: 53d4bb30-3f36-4e8a-b078-69d36c4a79ff

tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the execution of Xwizard tool with specific arguments which utilized to run custom class properties.

<!--more-->


## Known false-positives

* Unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Xwizard/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_class_exec_xwizard.yml))
```yaml
title: Custom Class Execution via Xwizard
id: 53d4bb30-3f36-4e8a-b078-69d36c4a79ff
status: test
description: Detects the execution of Xwizard tool with specific arguments which utilized to run custom class properties.
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\xwizard.exe'
    CommandLine|re: '{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}'
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218

```
