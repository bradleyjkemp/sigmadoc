---
title: "Buffer Overflow Attempts"
aliases:
  - "/rule/18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781"
ruleid: 18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781

tags:
  - attack.t1068
  - attack.privilege_escalation



status: stable





date: Wed, 1 Mar 2017 08:38:33 +0100


---

Detects buffer overflow attempts in Unix system log files

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/ossec/ossec-hids/blob/master/etc/rules/attack_rules.xml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_buffer_overflows.yml))
```yaml
title: Buffer Overflow Attempts
id: 18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781
status: stable
description: Detects buffer overflow attempts in Unix system log files
author: Florian Roth
date: 2017/03/01
references:
    - https://github.com/ossec/ossec-hids/blob/master/etc/rules/attack_rules.xml
logsource:
    product: unix
detection:
    keywords:
        - 'attempt to execute code on stack by'
        - 'FTP LOGIN FROM .* 0bin0sh'
        - 'rpc.statd[\d+]: gethostbyname error for'
        - 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    condition: keywords
falsepositives:
    - Unknown
level: high
tags:
    - attack.t1068
    - attack.privilege_escalation
```
