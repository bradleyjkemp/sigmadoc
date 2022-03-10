---
title: "CVE-2021-1675 Print Spooler Exploitation Filename Pattern"
aliases:
  - "/rule/2131cfb3-8c12-45e8-8fa0-31f5924e9f07"


tags:
  - attack.execution
  - attack.privilege_escalation
  - attack.resource_development
  - attack.t1587
  - cve.2021.1675



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the default filename used in PoC code against print spooler vulnerability CVE-2021-1675

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hhlxf/PrintNightmare
* https://github.com/afwu/PrintNightmare
* https://github.com/cube0x0/CVE-2021-1675


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_cve_2021_1675_printspooler.yml))
```yaml
title: CVE-2021-1675 Print Spooler Exploitation Filename Pattern
id: 2131cfb3-8c12-45e8-8fa0-31f5924e9f07
description: Detects the default filename used in PoC code against print spooler vulnerability CVE-2021-1675
author: Florian Roth
status: experimental
level: critical
references:
    - https://github.com/hhlxf/PrintNightmare
    - https://github.com/afwu/PrintNightmare
    - https://github.com/cube0x0/CVE-2021-1675
date: 2021/06/29
modified: 2021/12/01
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.resource_development
    - attack.t1587
    - cve.2021.1675
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: 
            - 'C:\Windows\System32\spool\drivers\x64\3\old\1\123'
    condition: selection
fields:
    - ComputerName
    - TargetFilename
falsepositives:
    - Unknown

```