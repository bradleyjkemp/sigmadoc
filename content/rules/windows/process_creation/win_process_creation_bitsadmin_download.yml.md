---
title: "Bitsadmin Download"
aliases:
  - "/rule/d059842b-6b9d-4ed1-b5c3-5b89143c6ede"

tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197
  - attack.s0190
  - attack.t1036.003



status: experimental



level: medium



date: Wed, 8 Mar 2017 22:49:35 -0800


---

Detects usage of bitsadmin downloading a file

<!--more-->


## Known false-positives

* Some legitimate apps use this, but limited.



## References

* https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
* https://isc.sans.edu/diary/22264


## Raw rule
```yaml
title: Bitsadmin Download
id: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
status: experimental
description: Detects usage of bitsadmin downloading a file
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
    - attack.t1036.003    
date: 2017/03/09
modified: 2020/09/06
author: Michael Haag
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\bitsadmin.exe'
        CommandLine:
            - '* /transfer *'
    selection2:
        CommandLine:
            - '*copy bitsadmin.exe*'
    condition: selection1 or selection2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Some legitimate apps use this, but limited.
level: medium

```
