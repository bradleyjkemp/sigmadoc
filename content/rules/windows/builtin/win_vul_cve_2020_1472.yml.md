---
title: "Vulnerable Netlogon Secure Channel Connection Allowed"
aliases:
  - "/rule/a0cb7110-edf0-47a4-9177-541a4083128a"

tags:
  - attack.privilege_escalation



date: Tue, 15 Sep 2020 15:13:53 +0200


---

Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.

<!--more-->


## Known false-positives

* Unknown



## References

* https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc


## Raw rule
```yaml
title: Vulnerable Netlogon Secure Channel Connection Allowed
id: a0cb7110-edf0-47a4-9177-541a4083128a
status: experimental
description: Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.
references:
    - https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc
author: NVISO
date: 2020/09/15
tags:
    - attack.privilege_escalation
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 5829
    condition: selection
fields:
    - SAMAccountName
falsepositives:
    - Unknown
level: high

```
