---
title: "Hydra Password Guessing Hack Tool"
aliases:
  - "/rule/aaafa146-074c-11eb-adc1-0242ac120002"


tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.001



status: test





date: Mon, 5 Oct 2020 23:05:27 +0300


---

Detects command line parameters used by Hydra password guessing hack tool

<!--more-->


## Known false-positives

* Software that uses the caret encased keywords PASS and USER in its command line



## References

* https://github.com/vanhauser-thc/thc-hydra
* https://attack.mitre.org/techniques/T1110/001/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_hack_hydra.yml))
```yaml
title: Hydra Password Guessing Hack Tool
id: aaafa146-074c-11eb-adc1-0242ac120002
status: test
description: Detects command line parameters used by Hydra password guessing hack tool
author: Vasiliy Burov
references:
  - https://github.com/vanhauser-thc/thc-hydra
  - https://attack.mitre.org/techniques/T1110/001/
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains|all:
      - '-u '
      - '-p '
  selection2:
    CommandLine|contains:
      - '^USER^'
      - '^PASS^'
  condition: selection1 and selection2
falsepositives:
  - Software that uses the caret encased keywords PASS and USER in its command line
level: high
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.001

```
