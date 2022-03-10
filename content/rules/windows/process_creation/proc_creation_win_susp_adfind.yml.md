---
title: "Suspicious AdFind Execution"
aliases:
  - "/rule/75df3b17-8bcc-4565-b89b-c9898acef911"


tags:
  - attack.discovery
  - attack.t1018
  - attack.t1087.002
  - attack.t1482
  - attack.t1069.002



status: experimental





date: Sat, 26 Sep 2020 21:34:06 +0700


---

Detects the execution of a AdFind for Active Directory enumeration

<!--more-->


## Known false-positives

* Administrative activity



## References

* https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
* https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md
* https://thedfirreport.com/2020/05/08/adfind-recon/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_adfind.yml))
```yaml
title: Suspicious AdFind Execution
id: 75df3b17-8bcc-4565-b89b-c9898acef911
status: experimental
description: Detects the execution of a AdFind for Active Directory enumeration 
references:
    - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
    - https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md
    - https://thedfirreport.com/2020/05/08/adfind-recon/
author: FPT.EagleEye Team, omkar72, oscd.community
date: 2020/09/26
modified: 2021/05/12
tags:
    - attack.discovery
    - attack.t1018
    - attack.t1087.002
    - attack.t1482
    - attack.t1069.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'objectcategory'
            - 'trustdmp'
            - 'dcmodes'
            - 'dclist'
            - 'computers_pwdnotreqd'
        Image|endswith: '\adfind.exe'
    condition: selection
falsepositives:
    - Administrative activity
level: medium

```