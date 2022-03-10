---
title: "Rclone Execution via Command Line or PowerShell"
aliases:
  - "/rule/cb7286ba-f207-44ab-b9e6-760d82b84253"


tags:
  - attack.exfiltration
  - attack.t1567.002



status: deprecated





date: Sun, 24 Oct 2021 11:02:55 -0500


---

Detects Rclone which is commonly used by ransomware groups for exfiltration

<!--more-->


## Known false-positives

* Legitimate Rclone usage (rare)



## References

* https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/deprecated/win_susp_rclone_exec.yml))
```yaml
title: Rclone Execution via Command Line or PowerShell
id: cb7286ba-f207-44ab-b9e6-760d82b84253
description: Detects Rclone which is commonly used by ransomware groups for exfiltration
status: deprecated
date: 2021/05/26
author: Aaron Greetham (@beardofbinary) - NCC Group
references:
    - https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
tags:
    - attack.exfiltration
    - attack.t1567.002
falsepositives:
    - Legitimate Rclone usage (rare)
level: high
logsource:
    product: windows
    category: process_creation
detection:
    exec_selection:
        Image|endswith: '\rclone.exe'
        ParentImage|endswith:
            - '\PowerShell.exe'
            - '\cmd.exe'
    command_selection:
        CommandLine|contains:
            - ' pass '
            - ' user '
            - ' copy '
            - ' mega '
            - ' sync '
            - ' config '
            - ' lsd '
            - ' remote '
            - ' ls '
    description_selection:
      Description: 'Rsync for cloud storage'
    condition: command_selection and ( description_selection or exec_selection )

```
