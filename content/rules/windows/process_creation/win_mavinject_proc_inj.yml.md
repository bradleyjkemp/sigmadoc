---
title: "MavInject Process Injection"
aliases:
  - "/rule/17eb8e57-9983-420d-ad8a-2c4976c22eb8"

tags:
  - attack.t1055
  - attack.t1055.001
  - attack.t1218



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects process injection using the signed Windows tool Mavinject32.exe

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/gN3mes1s/status/941315826107510784
* https://reaqta.com/2017/12/mavinject-microsoft-injector/
* https://twitter.com/Hexacorn/status/776122138063409152


## Raw rule
```yaml
title: MavInject Process Injection
id: 17eb8e57-9983-420d-ad8a-2c4976c22eb8
status: experimental
description: Detects process injection using the signed Windows tool Mavinject32.exe
references:
    - https://twitter.com/gN3mes1s/status/941315826107510784
    - https://reaqta.com/2017/12/mavinject-microsoft-injector/
    - https://twitter.com/Hexacorn/status/776122138063409152
author: Florian Roth
date: 2018/12/12
modified: 2020/09/01
tags:
    - attack.t1055          # an old one
    - attack.t1055.001
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* /INJECTRUNNING *'
    condition: selection
falsepositives:
    - unknown
level: critical

```