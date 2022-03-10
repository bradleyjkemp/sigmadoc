---
title: "Change User Agents with WebRequest"
aliases:
  - "/rule/d4488827-73af-4f8d-9244-7b7662ef046e"


tags:
  - attack.command_and_control
  - attack.t1071.001



status: experimental





date: Sun, 23 Jan 2022 16:37:59 +0100


---

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md#t1071001---web-protocols


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_susp_invoke_webrequest_useragent.yml))
```yaml
title: Change User Agents with WebRequest
id: d4488827-73af-4f8d-9244-7b7662ef046e
status: experimental
author: frack113
date: 2022/01/23
description: |
  Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
  Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md#t1071001---web-protocols
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - Invoke-WebRequest
            - '-UserAgent '
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001


```
