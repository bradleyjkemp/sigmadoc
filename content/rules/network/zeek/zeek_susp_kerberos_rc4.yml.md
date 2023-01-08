---
title: "Kerberos Network Traffic RC4 Ticket Encryption"
aliases:
  - "/rule/503fe26e-b5f2-4944-a126-eab405cc06e5"
ruleid: 503fe26e-b5f2-4944-a126-eab405cc06e5

tags:
  - attack.credential_access
  - attack.t1558.003



status: test





date: Wed, 12 Feb 2020 21:21:46 -0800


---

Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting

<!--more-->


## Known false-positives

* normal enterprise SPN requests activity



## References

* https://adsecurity.org/?p=3458


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/zeek/zeek_susp_kerberos_rc4.yml))
```yaml
title: Kerberos Network Traffic RC4 Ticket Encryption
id: 503fe26e-b5f2-4944-a126-eab405cc06e5
status: test
description: Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting
author: sigma
references:
  - https://adsecurity.org/?p=3458
date: 2020/02/12
modified: 2021/11/27
logsource:
  product: zeek
  service: kerberos
detection:
  selection:
    request_type: 'TGS'
    cipher: 'rc4-hmac'
  computer_acct:
    service|startswith: '$'
  condition: selection and not computer_acct
falsepositives:
  - normal enterprise SPN requests activity
level: medium
tags:
  - attack.credential_access
  - attack.t1558.003

```
