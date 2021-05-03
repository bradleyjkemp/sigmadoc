---
title: "Python SQL Exceptions"
aliases:
  - "/rule/19aefed0-ffd4-47dc-a7fc-f8b1425e84f9"

tags:
  - attack.initial_access
  - attack.t1190



date: Sat, 12 Aug 2017 00:44:18 +0200


---

Generic rule for SQL exceptions in Python according to PEP 249

<!--more-->


## Known false-positives

* Application bugs
* Penetration testing



## References

* https://www.python.org/dev/peps/pep-0249/#exceptions


## Raw rule
```yaml
title: Python SQL Exceptions
id: 19aefed0-ffd4-47dc-a7fc-f8b1425e84f9
status: stable
description: Generic rule for SQL exceptions in Python according to PEP 249
author: Thomas Patzke
date: 2017/08/12
modified: 2020/09/01
references:
    - https://www.python.org/dev/peps/pep-0249/#exceptions
logsource:
    category: application
    product: python
detection:
    exceptions:
        - DataError
        - IntegrityError
        - ProgrammingError
        - OperationalError
    condition: exceptions
falsepositives:
    - Application bugs
    - Penetration testing
level: medium
tags:
    - attack.initial_access
    - attack.t1190
```
