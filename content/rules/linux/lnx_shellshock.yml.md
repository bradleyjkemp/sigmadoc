---
title: "Shellshock Expression"
aliases:
  - "/rule/c67e0c98-4d39-46ee-8f6b-437ebf6b950e"



date: Tue, 14 Mar 2017 14:53:29 +0100


---

Detects shellshock expressions in log files

<!--more-->


## Known false-positives

* Unknown



## References

* http://rubular.com/r/zxBfjWfFYs


## Raw rule
```yaml
title: Shellshock Expression
id: c67e0c98-4d39-46ee-8f6b-437ebf6b950e
status: experimental
description: Detects shellshock expressions in log files
author: Florian Roth
date: 2017/03/14
references:
    - http://rubular.com/r/zxBfjWfFYs
logsource:
    product: linux
detection:
    expression:
        - /\(\)\s*\t*\{.*;\s*\}\s*;/
    condition: expression
falsepositives:
    - Unknown
level: high

```
