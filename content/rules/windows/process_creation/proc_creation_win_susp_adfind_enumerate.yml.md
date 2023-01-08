---
title: "Suspicious AdFind Enumerate"
aliases:
  - "/rule/455b9d50-15a1-4b99-853f-8d37655a4c1b"
ruleid: 455b9d50-15a1-4b99-853f-8d37655a4c1b

tags:
  - attack.discovery
  - attack.t1087.002



status: experimental





date: Mon, 13 Dec 2021 18:52:17 +0100


---

Detects the execution of a AdFind for enumeration

<!--more-->


## Known false-positives

* Administrative activity



## References

* https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_adfind_enumerate.yml))
```yaml
title: Suspicious AdFind Enumerate
id: 455b9d50-15a1-4b99-853f-8d37655a4c1b
status: experimental
description: Detects the execution of a AdFind for enumeration 
references:
    - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md
author: frack113
date: 2021/12/13
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\adfind.exe'
    test_5: #Listing password policy
        CommandLine|contains:
            - lockoutduration
            - lockoutthreshold
            - lockoutobservationwindow
            - maxpwdage
            - minpwdage
            - minpwdlength
            - pwdhistorylength
            - pwdproperties
    test_6: #Enumerate Active Directory Admins
        CommandLine|contains: '-sc admincountdmp' 
    test_8: #Enumerate Active Directory Exchange AD Objects
        CommandLine|contains: '-sc exchaddresses'
    condition: selection and 1 of test_*
falsepositives:
    - Administrative activity
level: medium
tags:
    - attack.discovery
    - attack.t1087.002
```
