---
title: "Kerberos Network Traffic RC4 Ticket Encryption"
aliases:
  - "/rule/503fe26e-b5f2-4944-a126-eab405cc06e5"

tags:
  - attack.credential_access
  - attack.t1208
  - attack.t1558.003



status: experimental



level: medium



date: Wed, 12 Feb 2020 21:21:46 -0800


---

Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting

<!--more-->


## Known false-positives

* normal enterprise SPN requests activity



## References

* https://adsecurity.org/?p=3458


## Raw rule
```yaml
title: Kerberos Network Traffic RC4 Ticket Encryption
id: 503fe26e-b5f2-4944-a126-eab405cc06e5
status: experimental
date: 2020/02/12
description: Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting
references:
    - https://adsecurity.org/?p=3458
tags:
    - attack.credential_access
    - attack.t1208 # an old one
    - attack.t1558.003
logsource:
    product: zeek
    service: kerberos
detection:
    selection:
        request_type: 'TGS'
        cipher: 'rc4-hmac'
    computer_acct:
        service: '$*'
    condition: selection and not computer_acct
falsepositives:
    - normal enterprise SPN requests activity
level: medium

```
