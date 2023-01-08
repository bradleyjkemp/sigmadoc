---
title: "Wsreset UAC Bypass"
aliases:
  - "/rule/bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae"
ruleid: bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae

tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002



status: test





date: Thu, 30 Jan 2020 18:05:47 +0100


---

Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC

<!--more-->


## Known false-positives

* Unknown sub processes of Wsreset.exe



## References

* https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
* https://www.activecyber.us/activelabs/windows-uac-bypass
* https://twitter.com/ReaQta/status/1222548288731217921


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_wsreset_uac_bypass.yml))
```yaml
title: Wsreset UAC Bypass
id: bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae
status: test
description: Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC
author: Florian Roth
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
  - https://www.activecyber.us/activelabs/windows-uac-bypass
  - https://twitter.com/ReaQta/status/1222548288731217921
date: 2020/01/30
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WSreset.exe'
  condition: selection
fields:
  - CommandLine
falsepositives:
  - Unknown sub processes of Wsreset.exe
level: high
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002

```
