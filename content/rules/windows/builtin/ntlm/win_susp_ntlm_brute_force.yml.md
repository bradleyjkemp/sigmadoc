---
title: "NTLM Brute Force"
aliases:
  - "/rule/9c8acf1a-cbf9-4db6-b63c-74baabe03e59"


tags:
  - attack.credential_access
  - attack.t1110



status: experimental





date: Wed, 2 Feb 2022 09:24:13 -0500


---

Detects common NTLM brute force device names

<!--more-->


## Known false-positives

* Systems with names equal to the spoofed ones used by the brute force tools



## References

* https://www.varonis.com/blog/investigate-ntlm-brute-force


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/ntlm/win_susp_ntlm_brute_force.yml))
```yaml
title: NTLM Brute Force
id: 9c8acf1a-cbf9-4db6-b63c-74baabe03e59
status: experimental
description: Detects common NTLM brute force device names
references:
    - https://www.varonis.com/blog/investigate-ntlm-brute-force
author: Jerry Shockley '@jsh0x'
date: 2022/02/02
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8004
    devicename:
        WorkstationName:
            - 'Rdesktop'
            - 'Remmina'
            - 'Freerdp'
            - 'Windows7'
            - 'Windows8'
            - 'Windows2012'
            - 'Windows2016'
            - 'Windows2019'
    condition: selection and devicename
falsepositives:
    - Systems with names equal to the spoofed ones used by the brute force tools 
level: medium

```
