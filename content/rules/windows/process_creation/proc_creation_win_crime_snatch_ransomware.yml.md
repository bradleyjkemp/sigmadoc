---
title: "Snatch Ransomware"
aliases:
  - "/rule/5325945e-f1f0-406e-97b8-65104d393fff"
ruleid: 5325945e-f1f0-406e-97b8-65104d393fff

tags:
  - attack.execution
  - attack.t1204



status: test





date: Wed, 26 Aug 2020 09:42:34 +0200


---

Detects specific process characteristics of Snatch ransomware word document droppers

<!--more-->


## Known false-positives

* Scripts that shutdown the system immediately and reboot them in safe mode are unlikely



## References

* https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_crime_snatch_ransomware.yml))
```yaml
title: Snatch Ransomware
id: 5325945e-f1f0-406e-97b8-65104d393fff
status: test
description: Detects specific process characteristics of Snatch ransomware word document droppers
author: Florian Roth
references:
  - https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/
date: 2020/08/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
    # Shutdown in safe mode immediately 
  selection:
    CommandLine|contains:
      - 'shutdown /r /f /t 00'
      - 'net stop SuperBackupMan'
  condition: selection
fields:
  - ComputerName
  - User
  - Image
falsepositives:
  - Scripts that shutdown the system immediately and reboot them in safe mode are unlikely
level: critical
tags:
  - attack.execution
  - attack.t1204

```