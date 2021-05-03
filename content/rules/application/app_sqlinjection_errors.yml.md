---
title: "Suspicious SQL Error Messages"
aliases:
  - "/rule/8a670c6d-7189-4b1c-8017-a417ca84a086"

tags:
  - attack.initial_access
  - attack.t1190



date: Mon, 27 Nov 2017 22:52:17 +0100


---

Detects SQL error messages that indicate probing for an injection attack

<!--more-->


## Known false-positives

* Application bugs



## References

* http://www.sqlinjection.net/errors


## Raw rule
```yaml
title: Suspicious SQL Error Messages
id: 8a670c6d-7189-4b1c-8017-a417ca84a086
status: experimental
description: Detects SQL error messages that indicate probing for an injection attack
author: Bjoern Kimminich
date: 2017/11/27
modified: 2020/09/01
references:
    - http://www.sqlinjection.net/errors
logsource:
    category: application
    product: sql
detection:
    keywords:
        # Oracle
        - quoted string not properly terminated
        # MySQL
        - You have an error in your SQL syntax
        # SQL Server
        - Unclosed quotation mark
        # SQLite
        - 'near "*": syntax error'
        - SELECTs to the left and right of UNION do not have the same number of result columns
    condition: keywords
falsepositives:
    - Application bugs
level: high
tags:
    - attack.initial_access
    - attack.t1190
```