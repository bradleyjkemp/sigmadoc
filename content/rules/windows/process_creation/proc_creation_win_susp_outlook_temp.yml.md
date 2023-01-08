---
title: "Execution in Outlook Temp Folder"
aliases:
  - "/rule/a018fdc3-46a3-44e5-9afb-2cd4af1d4b39"
ruleid: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39

tags:
  - attack.initial_access
  - attack.t1566.001



status: experimental





date: Tue, 1 Oct 2019 16:07:43 +0200


---

Detects a suspicious program execution in Outlook temp folder

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_outlook_temp.yml))
```yaml
title: Execution in Outlook Temp Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: experimental
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth
date: 2019/10/01
modified: 2021/06/27
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\Temporary Internet Files\Content.Outlook\'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
