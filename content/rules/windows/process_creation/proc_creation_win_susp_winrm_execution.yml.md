---
title: "Remote Code Execute via Winrm.vbs"
aliases:
  - "/rule/9df0dd3a-1a5c-47e3-a2bc-30ed177646a0"
ruleid: 9df0dd3a-1a5c-47e3-a2bc-30ed177646a0

tags:
  - attack.defense_evasion
  - attack.t1216



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects an attempt to execute code or create service on remote host via winrm.vbs.

<!--more-->


## Known false-positives

* Legitimate use for administartive purposes. Unlikely



## References

* https://twitter.com/bohops/status/994405551751815170
* https://redcanary.com/blog/lateral-movement-winrm-wmi/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_winrm_execution.yml))
```yaml
title: Remote Code Execute via Winrm.vbs
id: 9df0dd3a-1a5c-47e3-a2bc-30ed177646a0
status: test
description: Detects an attempt to execute code or create service on remote host via winrm.vbs.
author: Julia Fomina, oscd.community
references:
  - https://twitter.com/bohops/status/994405551751815170
  - https://redcanary.com/blog/lateral-movement-winrm-wmi/
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cscript.exe'
    CommandLine|contains|all:
      - 'winrm'
      - 'invoke Create wmicimv2/Win32_'
      - '-r:http'
  condition: selection
falsepositives:
  - Legitimate use for administartive purposes. Unlikely

level: medium
tags:
  - attack.defense_evasion
  - attack.t1216

```
