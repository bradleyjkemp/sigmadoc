---
title: "CVE-2021-26858 Exchange Exploitation"
aliases:
  - "/rule/b06335b3-55ac-4b41-937e-16b7f5d57dfd"


tags:
  - attack.t1203
  - attack.execution
  - cve.2021.26858



status: experimental





date: Wed, 3 Mar 2021 12:46:50 +0545


---

Detects possible successful exploitation for vulnerability described in CVE-2021-26858 by looking for | creation of non-standard files on disk by Exchange Server’s Unified Messaging service | which could indicate dropping web shells or other malicious content

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_cve_2021_26858_msexchange.yml))
```yaml
title: CVE-2021-26858 Exchange Exploitation
id: b06335b3-55ac-4b41-937e-16b7f5d57dfd
description: Detects possible successful exploitation for vulnerability described in CVE-2021-26858 by looking for |
             creation of non-standard files on disk by Exchange Server’s Unified Messaging service |
             which could indicate dropping web shells or other malicious content
author: Bhabesh Raj
status: experimental
references:
    - https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
date: 2021/03/03
tags:
    - attack.t1203
    - attack.execution
    - cve.2021.26858
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith: 'UMWorkerProcess.exe'
    filter:
        TargetFilename|endswith: 
            - 'CacheCleanup.bin'
            - '.txt'
            - '.LOG'
            - '.cfg'
            - 'cleanup.bin'
    condition: selection and not filter
fields:
    - ComputerName
    - TargetFilename
falsepositives:
    - Unknown
level: critical
```
