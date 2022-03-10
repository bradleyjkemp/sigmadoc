---
title: "PCRE.NET Package Image Load"
aliases:
  - "/rule/84b0a8f3-680b-4096-a45b-e9a89221727c"


tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects processes loading modules related to PCRE.NET package

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/rbmaslen/status/1321859647091970051
* https://twitter.com/tifkin_/status/1321916444557365248


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_pcre_net_load.yml))
```yaml
title: PCRE.NET Package Image Load
id: 84b0a8f3-680b-4096-a45b-e9a89221727c
description: Detects processes loading modules related to PCRE.NET package
status: experimental
date: 2020/10/29
modified: 2021/08/14
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.execution
    - attack.t1059
references:
    - https://twitter.com/rbmaslen/status/1321859647091970051
    - https://twitter.com/tifkin_/status/1321916444557365248
logsource:
    category: image_load
    product: windows
detection:
    selection: 
        ImageLoaded|contains: \AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\
    condition: selection
falsepositives:
    - Unknown
level: high

```
