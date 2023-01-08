---
title: "Clipboard Collection with Xclip Tool"
aliases:
  - "/rule/ec127035-a636-4b9a-8555-0efd4e59f316"
ruleid: ec127035-a636-4b9a-8555-0efd4e59f316

tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Fri, 15 Oct 2021 15:59:11 -0400


---

Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed. Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.

<!--more-->


## Known false-positives

* Legitimate usage of xclip tools.



## References

* https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_clipboard_collection.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_clipboard_collection.yml))
```yaml
title: Clipboard Collection with Xclip Tool
id: ec127035-a636-4b9a-8555-0efd4e59f316
status: experimental
description: Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed. Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
date: 2021/10/15
author: Pawel Mazur, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
tags:
    - attack.impact
    - attack.t1485
references:
   - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_clipboard_collection.yml
logsource:
   product: linux
   category: process_creation
detection:
    selection1:
      Image|contains: 'xclip'
    selection2:
      CommandLine|contains:
        - '-selection'
        - '-sel'
    selection3:
      CommandLine|contains:
        - 'clipboard'
        - 'clip'
    selection4:
      CommandLine|contains: '-o'
    condition: selection1 and selection2 and selection3 and selection4
falsepositives:
   - Legitimate usage of xclip tools.
level: low
```
