---
title: "Apache Threading Error"
aliases:
  - "/rule/e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c"



status: experimental



level: medium



date: Tue, 22 Jan 2019 08:49:10 +0100


---

Detects an issue in apache logs that reports threading related errors

<!--more-->


## Known false-positives

* https://bz.apache.org/bugzilla/show_bug.cgi?id=46185



## References

* https://github.com/hannob/apache-uaf/blob/master/README.md


## Raw rule
```yaml
title: Apache Threading Error
id: e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c
status: experimental
description: Detects an issue in apache logs that reports threading related errors
author: Florian Roth
date: 2019/01/22
references:
    - https://github.com/hannob/apache-uaf/blob/master/README.md
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
