---
title: "SecurityXploded Tool"
aliases:
  - "/rule/7679d464-4f74-45e2-9e01-ac66c5eb041a"
ruleid: 7679d464-4f74-45e2-9e01-ac66c5eb041a

tags:
  - attack.credential_access
  - attack.t1555



status: experimental





date: Mon, 30 Dec 2019 14:25:29 +0100


---

Detects the execution of SecurityXploded Tools

<!--more-->


## Known false-positives

* unlikely



## References

* https://securityxploded.com/
* https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_hack_secutyxploded.yml))
```yaml
title: SecurityXploded Tool
id: 7679d464-4f74-45e2-9e01-ac66c5eb041a
description: Detects the execution of SecurityXploded Tools
status: experimental
author: Florian Roth
references:
    - https://securityxploded.com/
    - https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/
date: 2018/12/19
modified: 2021/05/11
tags:
    - attack.credential_access
    - attack.t1555
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Company: SecurityXploded
    selection2:
        Image|endswith: 'PasswordDump.exe'
    selection3:
        OriginalFileName|endswith: 'PasswordDump.exe'
    condition: 1 of selection*
falsepositives:
    - unlikely
level: critical

```
