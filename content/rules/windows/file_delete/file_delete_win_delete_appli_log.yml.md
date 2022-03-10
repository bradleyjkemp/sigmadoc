---
title: "Delete Log from Application"
aliases:
  - "/rule/b1decb61-ed83-4339-8e95-53ea51901720"


tags:
  - attack.defense_evasion
  - attack.t1070.004



status: experimental





date: Sun, 16 Jan 2022 14:47:56 +0100


---

Deletion of log files is a known anti-forensic technique

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_delete/file_delete_win_delete_appli_log.yml))
```yaml
title: Delete Log from Application
id: b1decb61-ed83-4339-8e95-53ea51901720
status: experimental
description: Deletion of log files is a known anti-forensic technique
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md
date: 2022/01/16
logsource:
  product: windows
  category: file_delete
detection:
    selection_teamviewer:
        TargetFilename|endswith: '.log'
        TargetFilename|contains: '\TeamViewer_'
    filter: 
        Image: C:\Windows\system32\svchost.exe
    condition: selection_teamviewer and not filter
falsepositives:
  - unknown
level: low
tags:
    - attack.defense_evasion
    - attack.t1070.004

```
