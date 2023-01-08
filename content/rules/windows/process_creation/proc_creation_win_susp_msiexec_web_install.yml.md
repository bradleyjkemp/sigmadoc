---
title: "MsiExec Web Install"
aliases:
  - "/rule/f7b5f842-a6af-4da5-9e95-e32478f3cd2f"
ruleid: f7b5f842-a6af-4da5-9e95-e32478f3cd2f

tags:
  - attack.defense_evasion
  - attack.t1218.007
  - attack.command_and_control
  - attack.t1105



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious msiexec process starts with web addresses as parameter

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_msiexec_web_install.yml))
```yaml
title: MsiExec Web Install
id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
status: test
description: Detects suspicious msiexec process starts with web addresses as parameter
author: Florian Roth
references:
  - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
date: 2018/02/09
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - ' msiexec'
      - '://'
  condition: selection
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218.007
  - attack.command_and_control
  - attack.t1105

```
