---
title: "Powerup Write Hijack DLL"
aliases:
  - "/rule/602a1f13-c640-4d73-b053-be9a2fa58b96"


tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1574.001



status: experimental





date: Sat, 21 Aug 2021 17:47:56 +0530


---

Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation. In it's default mode, it builds a self deleting .bat file which executes malicious command. The detection rule relies on creation of the malicious bat file (debug.bat by default).

<!--more-->


## Known false-positives

* Pentest
* Any powershell script that creates bat files



## References

* https://powersploit.readthedocs.io/en/latest/Privesc/Write-HijackDll/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_detect_powerup_dllhijacking.yml))
```yaml
title: Powerup Write Hijack DLL
id: 602a1f13-c640-4d73-b053-be9a2fa58b96
status: experimental
description:
 Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation.
 In it's default mode, it builds a self deleting .bat file which executes malicious command. 
 The detection rule relies on creation of the malicious bat file (debug.bat by default).
references:
    - https://powersploit.readthedocs.io/en/latest/Privesc/Write-HijackDll/
author: Subhash Popuri (@pbssubhash)
date: 2021/08/21
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        TargetFilename|endswith: '.bat'
    condition: selection
falsepositives:
    - Pentest
    - Any powershell script that creates bat files # highly unlikely (untested)
level: high

```