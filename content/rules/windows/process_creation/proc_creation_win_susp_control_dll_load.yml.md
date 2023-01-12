---
title: "Suspicious Control Panel DLL Load"
aliases:
  - "/rule/d7eb979b-c2b5-4a6f-a3a7-c87ce6763819"
ruleid: d7eb979b-c2b5-4a6f-a3a7-c87ce6763819

tags:
  - attack.defense_evasion
  - attack.t1218.011



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/rikvduijn/status/853251879320662017


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_control_dll_load.yml))
```yaml
title: Suspicious Control Panel DLL Load
id: d7eb979b-c2b5-4a6f-a3a7-c87ce6763819
status: test
description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
author: Florian Roth
references:
  - https://twitter.com/rikvduijn/status/853251879320662017
date: 2017/04/15
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\System32\control.exe'
    Image|endswith: '\rundll32.exe '
  filter:
    CommandLine|contains: 'Shell32.dll'
  condition: selection and not filter
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011

```