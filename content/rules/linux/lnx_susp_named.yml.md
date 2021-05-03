---
title: "Suspicious Named Error"
aliases:
  - "/rule/c8e35e96-19ce-4f16-aeb6-fd5588dc5365"

tags:
  - attack.initial_access
  - attack.t1190



date: Tue, 20 Feb 2018 14:56:28 +0100


---

Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml


## Raw rule
```yaml
title: Suspicious Named Error
id: c8e35e96-19ce-4f16-aeb6-fd5588dc5365
status: experimental
description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
author: Florian Roth
date: 2018/02/20
references:
    - https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
logsource:
    product: linux
    service: syslog
detection:
    keywords:
        - '* dropping source port zero packet from *'
        - '* denied AXFR from *'
        - '* exiting (due to fatal error)*'
    condition: keywords
falsepositives:
    - Unknown
level: high
tags:
    - attack.initial_access
    - attack.t1190
```