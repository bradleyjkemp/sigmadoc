---
title: "Executable in ADS"
aliases:
  - "/rule/b69888d4-380c-45ce-9cf9-d9ce46e67821"

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.s0139
  - attack.t1564.004



status: experimental



level: critical



date: Sun, 3 Jun 2018 02:08:39 +0200


---

Detects the creation of an ADS data stream that contains an executable (non-empty imphash)

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/0xrawsec/status/1002478725605273600?s=21


## Raw rule
```yaml
title: Executable in ADS
id: b69888d4-380c-45ce-9cf9-d9ce46e67821
status: experimental
description: Detects the creation of an ADS data stream that contains an executable (non-empty imphash)
references:
    - https://twitter.com/0xrawsec/status/1002478725605273600?s=21
tags:
    - attack.defense_evasion
    - attack.t1027          # an old one
    - attack.s0139
    - attack.t1564.004
author: Florian Roth, @0xrawsec
date: 2018/06/03
modified: 2020/08/26
logsource:
    product: windows
    service: sysmon
    definition: 'Requirements: Sysmon config with Imphash logging activated'
detection:
    selection:
        EventID: 15
    filter1:
        Imphash: '00000000000000000000000000000000'
    filter2:
        Imphash: null
    condition: selection and not 1 of filter*
fields:
    - TargetFilename
    - Image
falsepositives:
    - unknown
level: critical


```
