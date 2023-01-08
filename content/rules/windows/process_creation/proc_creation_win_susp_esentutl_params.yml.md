---
title: "Esentutl Gather Credentials"
aliases:
  - "/rule/7df1713a-1a5b-4a4b-a071-dc83b144a101"
ruleid: 7df1713a-1a5b-4a4b-a071-dc83b144a101

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.003



status: experimental





date: Fri, 6 Aug 2021 00:55:57 +0400


---

Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.

<!--more-->


## Known false-positives

* To be determined



## References

* https://twitter.com/vxunderground/status/1423336151860002816
* https://attack.mitre.org/software/S0404/
* https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_esentutl_params.yml))
```yaml
title: Esentutl Gather Credentials
id: 7df1713a-1a5b-4a4b-a071-dc83b144a101
status: experimental
author: sam0x90
date: 2021/08/06
description: Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.
references:
    - https://twitter.com/vxunderground/status/1423336151860002816
    - https://attack.mitre.org/software/S0404/
    - https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'esentutl'
            - ' /p'
    condition: selection
falsepositives:
    - To be determined
level: medium
fields:
    - User
    - CommandLine
    - ParentCommandLine
    - CurrentDirectory

```
