---
title: "Suspicious Reconnaissance Activity"
aliases:
  - "/rule/d95de845-b83c-4a9a-8a6a-4fc802ebf6c0"
ruleid: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0

tags:
  - attack.discovery
  - attack.t1087.001
  - attack.t1087.002



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious command line activity on Windows systems

<!--more-->


## Known false-positives

* Inventory tool runs
* Penetration tests
* Administrative activity



## References

* https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
* https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_recon_activity.yml))
```yaml
title: Suspicious Reconnaissance Activity
id: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0
status: experimental
description: Detects suspicious command line activity on Windows systems
author: Florian Roth, omkar72
date: 2019/01/16
modified: 2021/08/09
references:
    - https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - net group "domain admins" /dom
            - net localgroup administrators
            - net group "enterprise admins" /dom
            - net accounts /dom
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Inventory tool runs
    - Penetration tests
    - Administrative activity
analysis:
    recommendation: Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
level: medium

```
