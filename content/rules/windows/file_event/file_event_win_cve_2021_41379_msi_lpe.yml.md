---
title: "InstallerFileTakeOver LPE CVE-2021-41379 File Create Event"
aliases:
  - "/rule/3be82d5d-09fe-4d6a-a275-0d40d234d324"


tags:
  - attack.privilege_escalation
  - attack.t1068



status: experimental





date: Mon, 22 Nov 2021 14:15:51 +0100


---

Detects signs of the exploitation of LPE CVE-2021-41379 that include an msiexec process that creates an elevation_service.exe file

<!--more-->


## Known false-positives

* Unknown
* Possibly some Microsoft Edge upgrades



## References

* https://github.com/klinix5/InstallerFileTakeOver
* https://www.zerodayinitiative.com/advisories/ZDI-21-1308/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_cve_2021_41379_msi_lpe.yml))
```yaml
title: InstallerFileTakeOver LPE CVE-2021-41379 File Create Event
id: 3be82d5d-09fe-4d6a-a275-0d40d234d324
status: experimental
description: Detects signs of the exploitation of LPE CVE-2021-41379 that include an msiexec process that creates an elevation_service.exe file
author: Florian Roth
date: 2021/11/22
references:
    - https://github.com/klinix5/InstallerFileTakeOver
    - https://www.zerodayinitiative.com/advisories/ZDI-21-1308/
tags:
    - attack.privilege_escalation
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith: '\msiexec.exe'
        TargetFilename|startswith: 'C:\Program Files (x86)\Microsoft\Edge\Application'
        TargetFilename|endswith: '\elevation_service.exe'
    condition: selection
fields:
    - ComputerName
    - TargetFilename
falsepositives:
    - Unknown
    - Possibly some Microsoft Edge upgrades
level: critical

```
