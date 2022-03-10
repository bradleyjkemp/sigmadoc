---
title: "Apache Segmentation Fault"
aliases:
  - "/rule/1da8ce0b-855d-4004-8860-7d64d42063b1"


tags:
  - attack.impact
  - attack.t1499.004



status: test





date: Tue, 28 Feb 2017 17:53:06 +0100


---

Detects a segmentation fault error message caused by a creashing apache worker process

<!--more-->


## Known false-positives

* Unknown



## References

* http://www.securityfocus.com/infocus/1633


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_apache_segfault.yml))
```yaml
title: Apache Segmentation Fault
id: 1da8ce0b-855d-4004-8860-7d64d42063b1
status: test
description: Detects a segmentation fault error message caused by a creashing apache worker process
author: Florian Roth
references:
  - http://www.securityfocus.com/infocus/1633
date: 2017/02/28
modified: 2021/11/27
logsource:
  product: apache
detection:
  keywords:
    - 'exit signal Segmentation Fault'
  condition: keywords
falsepositives:
  - Unknown
level: high
tags:
  - attack.impact
  - attack.t1499.004

```