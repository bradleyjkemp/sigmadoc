---
title: "Suspicious Rundll32 Activity Invoking Sys File"
aliases:
  - "/rule/731231b9-0b5d-4219-94dd-abb6959aa7ea"


tags:
  - attack.defense_evasion
  - attack.t1218.011



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_sys.yml))
```yaml
title: Suspicious Rundll32 Activity Invoking Sys File
id: 731231b9-0b5d-4219-94dd-abb6959aa7ea
description: Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452
status: experimental
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
tags:
    - attack.defense_evasion
    - attack.t1218.011
author: Florian Roth
date: 2021/03/05
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: 'rundll32.exe'
    selection2:
        CommandLine|contains:
            - '.sys,'
            - '.sys '
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: high

```
