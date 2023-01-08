---
title: "Decode Base64 Encoded Text"
aliases:
  - "/rule/719c22d7-c11a-4f2c-93a6-2cfdd5412f68"
ruleid: 719c22d7-c11a-4f2c-93a6-2cfdd5412f68

tags:
  - attack.defense_evasion
  - attack.t1027



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects usage of base64 utility to decode arbitrary base64-encoded text

<!--more-->


## Known false-positives

* Legitimate activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_base64_decode.yml))
```yaml
title: Decode Base64 Encoded Text
id: 719c22d7-c11a-4f2c-93a6-2cfdd5412f68
status: test
description: Detects usage of base64 utility to decode arbitrary base64-encoded text
author: Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  base64_execution:
    Image: '/usr/bin/base64'
    CommandLine|contains: '-d'
  condition: base64_execution
falsepositives:
  - Legitimate activities
level: low
tags:
  - attack.defense_evasion
  - attack.t1027

```
