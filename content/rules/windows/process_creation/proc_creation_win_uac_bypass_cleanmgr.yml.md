---
title: "UAC Bypass Using Disk Cleanup"
aliases:
  - "/rule/b697e69c-746f-4a86-9f59-7bfff8eab881"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.yml))
```yaml
title: UAC Bypass Using Disk Cleanup
id: b697e69c-746f-4a86-9f59-7bfff8eab881
description: Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)
author: Christian Burkard
date: 2021/08/30
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith: '"\system32\cleanmgr.exe /autoclean /d C:'
        ParentCommandLine: 'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'
        IntegrityLevel:
          - 'High'
          - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
