---
title: "Executable in ADS"
aliases:
  - "/rule/b69888d4-380c-45ce-9cf9-d9ce46e67821"


tags:
  - attack.defense_evasion
  - attack.s0139
  - attack.t1564.004



status: test





date: Sun, 3 Jun 2018 02:08:39 +0200


---

Detects the creation of an ADS data stream that contains an executable (non-empty imphash)

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/0xrawsec/status/1002478725605273600?s=21


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/create_stream_hash/sysmon_ads_executable.yml))
```yaml
title: Executable in ADS
id: b69888d4-380c-45ce-9cf9-d9ce46e67821
status: test
description: Detects the creation of an ADS data stream that contains an executable (non-empty imphash)
author: Florian Roth, @0xrawsec
references:
  - https://twitter.com/0xrawsec/status/1002478725605273600?s=21
date: 2018/06/03
modified: 2021/12/08
logsource:
  product: windows
  category: create_stream_hash
  definition: 'Requirements: Sysmon config with Imphash logging activated'
detection:
  selection:
    Hashes|contains: 'IMPHASH='
  filter:
    Hashes|contains: 'IMPHASH=00000000000000000000000000000000'
  condition: selection and not filter
fields:
  - TargetFilename
  - Image
falsepositives:
  - unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.s0139
  - attack.t1564.004

```
