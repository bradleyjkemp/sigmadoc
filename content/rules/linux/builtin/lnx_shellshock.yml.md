---
title: "Shellshock Expression"
aliases:
  - "/rule/c67e0c98-4d39-46ee-8f6b-437ebf6b950e"


tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Tue, 14 Mar 2017 14:53:29 +0100


---

Detects shellshock expressions in log files

<!--more-->


## Known false-positives

* Unknown



## References

* https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_shellshock.yml))
```yaml
title: Shellshock Expression
id: c67e0c98-4d39-46ee-8f6b-437ebf6b950e
status: experimental
description: Detects shellshock expressions in log files
author: Florian Roth
date: 2017/03/14
modified: 2021/04/28
references:
    - https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf
logsource:
    product: linux
detection:
    keyword: 
        - '(){:;};'
        - '() {:;};'
        - '() { :;};'
        - '() { :; };'
    condition: keyword
falsepositives:
    - Unknown
level: high
tags:
    - attack.persistence
    - attack.t1505.003 
```
