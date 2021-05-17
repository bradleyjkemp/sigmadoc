---
title: "Space After Filename"
aliases:
  - "/rule/879c3015-c88b-4782-93d7-07adf92dbcb7"

tags:
  - attack.execution



status: experimental



level: low



date: Mon, 13 Jul 2020 01:33:39 +0300


---

Detects space after filename

<!--more-->


## Known false-positives

* Typos



## References

* https://attack.mitre.org/techniques/T1064


## Raw rule
```yaml
title: Space After Filename
id: 879c3015-c88b-4782-93d7-07adf92dbcb7 
status: experimental
description: Detects space after filename
author: Ömer Günal
date: 2020/06/17
references:
    - https://attack.mitre.org/techniques/T1064
level: low
logsource:
    product: linux
detection:
    selection1:
        - 'echo "*" > * && chmod +x *'
    selection2:
        - 'mv * "* "'
    condition: selection1 and selection2 
falsepositives:
    - Typos
tags:
    - attack.execution
```
