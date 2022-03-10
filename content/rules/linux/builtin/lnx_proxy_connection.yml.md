---
title: "Connection Proxy"
aliases:
  - "/rule/72f4ab3f-787d-495d-a55d-68c2ff46cf4c"


tags:
  - attack.defense_evasion



status: test





date: Mon, 13 Jul 2020 01:31:05 +0300


---

Detects setting proxy

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://attack.mitre.org/techniques/T1090/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_proxy_connection.yml))
```yaml
title: Connection Proxy
id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: test
description: Detects setting proxy
author: Ömer Günal
references:
  - https://attack.mitre.org/techniques/T1090/
date: 2020/06/17
modified: 2021/11/27
logsource:
  product: linux
detection:
  keyword:
    - 'http_proxy=*'
    - 'https_proxy=*'
  condition: keyword
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.defense_evasion

```
