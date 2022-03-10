---
title: "Windows Spooler Service Suspicious File Deletion"
aliases:
  - "/rule/5b2bbc47-dead-4ef7-8908-0cf73fcbecbf"


tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1574
  - cve.2021.1675



status: experimental





date: Thu, 1 Jul 2021 16:33:55 +0545


---

Detect DLL deletions from Spooler Service driver folder

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hhlxf/PrintNightmare
* https://github.com/cube0x0/CVE-2021-1675


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_delete/file_delete_win_cve_2021_1675_printspooler_del.yml))
```yaml
title: Windows Spooler Service Suspicious File Deletion
id: 5b2bbc47-dead-4ef7-8908-0cf73fcbecbf
status: experimental
description: Detect DLL deletions from Spooler Service driver folder 
references:
    - https://github.com/hhlxf/PrintNightmare
    - https://github.com/cube0x0/CVE-2021-1675
author: Bhabesh Raj
date: 2021/07/01
modified: 2021/08/24
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1574
    - cve.2021.1675
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        Image|endswith: 'spoolsv.exe'
        TargetFilename|contains: 'C:\Windows\System32\spool\drivers\x64\3\'
    condition: selection
falsepositives:
    - Unknown
level: high

```
