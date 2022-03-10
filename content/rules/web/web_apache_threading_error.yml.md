---
title: "Apache Threading Error"
aliases:
  - "/rule/e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c"




status: test





date: Tue, 22 Jan 2019 08:49:10 +0100


---

Detects an issue in apache logs that reports threading related errors

<!--more-->


## Known false-positives

* https://bz.apache.org/bugzilla/show_bug.cgi?id=46185



## References

* https://github.com/hannob/apache-uaf/blob/master/README.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_apache_threading_error.yml))
```yaml
title: Apache Threading Error
id: e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c
status: test
description: Detects an issue in apache logs that reports threading related errors
author: Florian Roth
references:
  - https://github.com/hannob/apache-uaf/blob/master/README.md
date: 2019/01/22
modified: 2021/11/27
logsource:
  product: apache
detection:
  keywords:
    - '__pthread_tpp_change_priority: Assertion `new_prio == -1 || (new_prio >= fifo_min_prio && new_prio <= fifo_max_prio)'
  condition: keywords
falsepositives:
  - https://bz.apache.org/bugzilla/show_bug.cgi?id=46185
level: medium

```
