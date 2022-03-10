---
title: "Suspicious Named Error"
aliases:
  - "/rule/c8e35e96-19ce-4f16-aeb6-fd5588dc5365"


tags:
  - attack.initial_access
  - attack.t1190



status: test





date: Tue, 20 Feb 2018 14:56:28 +0100


---

Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/other/lnx_susp_named.yml))
```yaml
title: Suspicious Named Error
id: c8e35e96-19ce-4f16-aeb6-fd5588dc5365
status: test
description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
author: Florian Roth
references:
  - https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
date: 2018/02/20
modified: 2021/11/27
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
