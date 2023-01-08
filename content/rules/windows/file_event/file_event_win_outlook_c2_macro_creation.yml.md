---
title: "Outlook C2 Macro Creation"
aliases:
  - "/rule/8c31f563-f9a7-450c-bfa8-35f8f32f1f61"
ruleid: 8c31f563-f9a7-450c-bfa8-35f8f32f1f61

tags:
  - attack.persistence
  - attack.command_and_control
  - attack.t1137
  - attack.t1008
  - attack.t1546



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the creation of a macro file for Outlook. Goes with win_outlook_c2_registry_key. VbaProject.OTM is explicitly mentioned in T1137. Particularly interesting if both events Registry & File Creation happens at the same time.

<!--more-->


## Known false-positives

* User genuinly creates a VB Macro for their email



## References

* https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_outlook_c2_macro_creation.yml))
```yaml
title: Outlook C2 Macro Creation
id: 8c31f563-f9a7-450c-bfa8-35f8f32f1f61
status: experimental
description: Detects the creation of a macro file for Outlook. Goes with win_outlook_c2_registry_key. VbaProject.OTM is explicitly mentioned in T1137. Particularly interesting if both events Registry & File Creation happens at the same time. 
references:
    - https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
author: '@ScoubiMtl'
tags:
    - attack.persistence
    - attack.command_and_control
    - attack.t1137
    - attack.t1008
    - attack.t1546
date: 2021/04/05
logsource:
    category: file_event
    product: windows
detection:
    selection:        
        TargetFilename|endswith: '\Microsoft\Outlook\VbaProject.OTM'
    condition: selection
falsepositives:
    - User genuinly creates a VB Macro for their email
level: medium

```
