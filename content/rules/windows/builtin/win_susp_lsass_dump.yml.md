---
title: "Password Dumper Activity on LSASS"
aliases:
  - "/rule/aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001



status: experimental



level: high



date: Fri, 10 Feb 2017 19:17:02 +0100


---

Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN

<!--more-->


## Known false-positives

* Unkown



## References

* https://twitter.com/jackcr/status/807385668833968128


## Raw rule
```yaml
title: Password Dumper Activity on LSASS
id: aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
status: experimental
date: 2017/02/12
references:
    - https://twitter.com/jackcr/status/807385668833968128
tags:
    - attack.credential_access
    - attack.t1003           # an old one
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ProcessName: 'C:\Windows\System32\lsass.exe'
        AccessMask: '0x705'
        ObjectType: 'SAM_DOMAIN'
    condition: selection
falsepositives:
    - Unkown
level: high

```
