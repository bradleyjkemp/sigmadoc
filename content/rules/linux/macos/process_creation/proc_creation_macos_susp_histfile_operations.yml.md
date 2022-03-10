---
title: "Suspicious History File Operations"
aliases:
  - "/rule/508a9374-ad52-4789-b568-fc358def2c65"


tags:
  - attack.credential_access
  - attack.t1552.003



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects commandline operations on shell history files

<!--more-->


## Known false-positives

* Legitimate administrative activity
* Ligitimate software, cleaning hist file



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.003/T1552.003.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_susp_histfile_operations.yml))
```yaml
title: 'Suspicious History File Operations'
id: 508a9374-ad52-4789-b568-fc358def2c65
status: test
description: 'Detects commandline operations on shell history files'
author: 'Mikhail Larin, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.003/T1552.003.md
date: 2020/10/17
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '.bash_history'
      - '.zsh_history'
      - '.zhistory'
      - '.history'
      - '.sh_history'
      - 'fish_history'
  condition: selection
falsepositives:
  - 'Legitimate administrative activity'
  - 'Ligitimate software, cleaning hist file'
level: medium
tags:
  - attack.credential_access
  - attack.t1552.003

```
