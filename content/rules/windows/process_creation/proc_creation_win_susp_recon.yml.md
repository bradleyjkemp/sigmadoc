---
title: "Recon Information for Export with Command Prompt"
aliases:
  - "/rule/aa2efee7-34dd-446e-8a37-40790a66efd7"


tags:
  - attack.collection
  - attack.t1119



status: experimental





date: Fri, 30 Jul 2021 08:15:13 +0200


---

Once established within a system or network, an adversary may use automated techniques for collecting internal data.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_recon.yml))
```yaml
title: Recon Information for Export with Command Prompt
id: aa2efee7-34dd-446e-8a37-40790a66efd7
status: experimental
author: frack113
date: 2021/07/30
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md
tags:
    - attack.collection
    - attack.t1119
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        Image|endswith:
            - '\tree.com'
            - '\WMIC.exe'
            - '\doskey.exe'
            - '\sc.exe'
    selection_redirect:
        ParentCommandLine|contains: ' > %TEMP%\'
    condition: selection_image and selection_redirect
falsepositives:
    - Unknown
level: medium

```
