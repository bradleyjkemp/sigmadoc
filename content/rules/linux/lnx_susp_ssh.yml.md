---
title: "Suspicious OpenSSH Daemon Error"
aliases:
  - "/rule/e76b413a-83d0-4b94-8e4c-85db4a5b8bdc"

tags:
  - attack.initial_access
  - attack.t1190



date: Fri, 30 Jun 2017 08:47:56 +0200


---

Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/openssh/openssh-portable/blob/master/ssherr.c
* https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml


## Raw rule
```yaml
title: Suspicious OpenSSH Daemon Error
id: e76b413a-83d0-4b94-8e4c-85db4a5b8bdc
status: experimental
description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
author: Florian Roth
date: 2017/06/30
modified: 2020/05/15
references:
    - https://github.com/openssh/openssh-portable/blob/master/ssherr.c
    - https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
logsource:
    product: linux
    service: sshd
detection:
    keywords:
        - '*unexpected internal error*'
        - '*unknown or unsupported key type*'
        - '*invalid certificate signing key*'
        - '*invalid elliptic curve value*'
        - '*incorrect signature*'
        - '*error in libcrypto*'
        - '*unexpected bytes remain after decoding*'
        - '*fatal: buffer_get_string: bad string*'
        - '*Local: crc32 compensation attack*'
        - '*bad client public DH value*'
        - '*Corrupted MAC on input*'
    condition: keywords
falsepositives:
    - Unknown
level: medium
tags:
    - attack.initial_access
    - attack.t1190
```