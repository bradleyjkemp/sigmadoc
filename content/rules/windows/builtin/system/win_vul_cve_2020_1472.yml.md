---
title: "Vulnerable Netlogon Secure Channel Connection Allowed"
aliases:
  - "/rule/a0cb7110-edf0-47a4-9177-541a4083128a"
ruleid: a0cb7110-edf0-47a4-9177-541a4083128a

tags:
  - attack.privilege_escalation
  - attack.t1548



status: experimental





date: Tue, 15 Sep 2020 15:13:53 +0200


---

Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.

<!--more-->


## Known false-positives

* Unknown



## References

* https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_vul_cve_2020_1472.yml))
```yaml
title: Vulnerable Netlogon Secure Channel Connection Allowed
id: a0cb7110-edf0-47a4-9177-541a4083128a
status: experimental
description: Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.
references:
    - https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc
author: NVISO
date: 2020/09/15
modified: 2021/11/30
tags:
    - attack.privilege_escalation
    - attack.t1548
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: NetLogon  # Active Directory: NetLogon ETW GUID {F33959B4-DBEC-11D2-895B-00C04F79AB69}
        EventID: 5829
    condition: selection
fields:
    - SAMAccountName
falsepositives:
    - Unknown
level: high

```
