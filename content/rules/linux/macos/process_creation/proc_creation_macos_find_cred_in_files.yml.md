---
title: "Credentials In Files"
aliases:
  - "/rule/53b1b378-9b06-4992-b972-dde6e423d2b4"


tags:
  - attack.credential_access
  - attack.t1552.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detecting attempts to extract passwords with grep and laZagne

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_find_cred_in_files.yml))
```yaml
title: 'Credentials In Files'
id: 53b1b378-9b06-4992-b972-dde6e423d2b4
status: test
description: 'Detecting attempts to extract passwords with grep and laZagne'
author: 'Igor Fits, Mikhail Larin, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection1:
    Image|endswith:
      - '/grep'
    CommandLine|contains:
      - 'password'
  selection2:
    CommandLine|contains: 'laZagne'
  condition: selection1 or selection2
falsepositives:
  - 'Unknown'
level: high
tags:
  - attack.credential_access
  - attack.t1552.001

```
