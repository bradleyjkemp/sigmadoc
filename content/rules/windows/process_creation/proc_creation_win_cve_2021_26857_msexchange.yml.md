---
title: "CVE-2021-26857 Exchange Exploitation"
aliases:
  - "/rule/cd479ccc-d8f0-4c66-ba7d-e06286f3f887"


tags:
  - attack.t1203
  - attack.execution
  - cve.2021.26857



status: stable





date: Wed, 3 Mar 2021 12:46:50 +0545


---

Detects possible successful exploitation for vulnerability described in CVE-2021-26857 by looking for | abnormal subprocesses spawning by Exchange Server’s Unified Messaging service

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cve_2021_26857_msexchange.yml))
```yaml
title: CVE-2021-26857 Exchange Exploitation
id: cd479ccc-d8f0-4c66-ba7d-e06286f3f887
description: Detects possible successful exploitation for vulnerability described in CVE-2021-26857 by looking for |
             abnormal subprocesses spawning by Exchange Server’s Unified Messaging service
author: Bhabesh Raj
status: stable
level: critical
references:
    - https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
date: 2021/03/03
tags:
    - attack.t1203
    - attack.execution
    - cve.2021.26857
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: 'UMWorkerProcess.exe'
    filter:
        Image|endswith:
            - 'wermgr.exe'
            - 'WerFault.exe'
    condition: selection and not filter
falsepositives:
    - Unknown

```
