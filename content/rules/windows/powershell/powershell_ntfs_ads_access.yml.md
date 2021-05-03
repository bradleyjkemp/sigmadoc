---
title: "NTFS Alternate Data Stream"
aliases:
  - "/rule/8c521530-5169-495d-a199-0a3a881ad24e"

tags:
  - attack.defense_evasion
  - attack.t1564.004
  - attack.t1096
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Tue, 24 Jul 2018 19:49:08 +0200


---

Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.

<!--more-->


## Known false-positives

* unknown



## References

* http://www.powertheshell.com/ntfsstreams/


## Raw rule
```yaml
title: NTFS Alternate Data Stream
id: 8c521530-5169-495d-a199-0a3a881ad24e
status: experimental
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
references:
    - http://www.powertheshell.com/ntfsstreams/
tags:
    - attack.defense_evasion
    - attack.t1564.004
    - attack.t1096  # an old one
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
author: Sami Ruohonen
date: 2018/07/24
modified: 2020/08/24
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keyword1:
        - "set-content"
        - "add-content"
    keyword2:
        - "-stream"
    condition: keyword1 and keyword2
falsepositives:
    - unknown
level: high

```