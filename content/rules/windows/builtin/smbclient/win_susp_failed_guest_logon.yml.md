---
title: "Suspicious Rejected SMB Guest Logon From IP"
aliases:
  - "/rule/71886b70-d7b4-4dbf-acce-87d2ca135262"


tags:
  - attack.credential_access
  - attack.t1110.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detect Attempt PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service

<!--more-->


## Known false-positives

* Account fallback reasons (after failed login with specific account)



## References

* https://twitter.com/KevTheHermit/status/1410203844064301056
* https://github.com/hhlxf/PrintNightmare
* https://github.com/afwu/PrintNightmare


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/smbclient/win_susp_failed_guest_logon.yml))
```yaml
title: Suspicious Rejected SMB Guest Logon From IP
id: 71886b70-d7b4-4dbf-acce-87d2ca135262
description: Detect Attempt PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service
author: Florian Roth, KevTheHermit, fuzzyf10w
status: experimental
level: medium
references:
    - https://twitter.com/KevTheHermit/status/1410203844064301056
    - https://github.com/hhlxf/PrintNightmare
    - https://github.com/afwu/PrintNightmare
date: 2021/06/30
modified: 2021/07/05
logsource:
    product: windows
    service: smbclient-security
detection:
    selection:
        EventID: 31017
        Description|contains: 'Rejected an insecure guest logon'
        UserName: ''
        ServerName|startswith: '\1'
    condition: selection
fields:
    - Computer
    - User
falsepositives:
    - Account fallback reasons (after failed login with specific account)
tags:
    - attack.credential_access
    - attack.t1110.001
```
