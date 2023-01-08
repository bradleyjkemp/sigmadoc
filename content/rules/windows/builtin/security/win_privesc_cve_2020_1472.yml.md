---
title: "Possible Zerologon (CVE-2020-1472) Exploitation"
aliases:
  - "/rule/dd7876d8-0f09-11eb-adc1-0242ac120002"
ruleid: dd7876d8-0f09-11eb-adc1-0242ac120002

tags:
  - attack.t1068
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Netlogon Elevation of Privilege Vulnerability aka Zerologon (CVE-2020-1472)

<!--more-->


## Known false-positives

* automatic DC computer account password change
* legitimate DC computer account password change



## References

* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472
* https://www.logpoint.com/en/blog/detecting-zerologon-vulnerability-in-logpoint/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_privesc_cve_2020_1472.yml))
```yaml
title: 'Possible Zerologon (CVE-2020-1472) Exploitation'
id: dd7876d8-0f09-11eb-adc1-0242ac120002
status: experimental
description: Detects Netlogon Elevation of Privilege Vulnerability aka Zerologon (CVE-2020-1472)
references:
    - https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472
    - https://www.logpoint.com/en/blog/detecting-zerologon-vulnerability-in-logpoint/
author: 'Aleksandr Akhremchik, @aleqs4ndr, ocsd.community'
date: 2020/10/15
modified: 2021/07/07
tags:
    - attack.t1068
    - attack.privilege_escalation
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4742
        SubjectUserName: 'ANONYMOUS LOGON'
        TargetUserName: '%DC-MACHINE-NAME%' # DC machine account name that ends with '$'
    filter:
        PasswordLastSet: '-'
    condition: selection and not filter
falsepositives:
    - automatic DC computer account password change
    - legitimate DC computer account password change
level: high

```
