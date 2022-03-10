---
title: "MavInject Process Injection"
aliases:
  - "/rule/17eb8e57-9983-420d-ad8a-2c4976c22eb8"


tags:
  - attack.t1055.001
  - attack.t1218



status: test





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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mavinject_proc_inj.yml))
```yaml
title: MavInject Process Injection
id: 17eb8e57-9983-420d-ad8a-2c4976c22eb8
status: test
description: Detects process injection using the signed Windows tool Mavinject32.exe
author: Florian Roth
references:
  - https://twitter.com/gN3mes1s/status/941315826107510784
  - https://reaqta.com/2017/12/mavinject-microsoft-injector/
  - https://twitter.com/Hexacorn/status/776122138063409152
date: 2018/12/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: ' /INJECTRUNNING '
  condition: selection
falsepositives:
  - unknown
level: critical
tags:
  - attack.t1055.001
  - attack.t1218

```
