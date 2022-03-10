---
title: "NetNTLM Downgrade Attack"
aliases:
  - "/rule/d67572a0-e2ec-45d6-b8db-c100d14b8ef2"


tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.t1112



status: experimental





date: Tue, 20 Mar 2018 11:07:21 +0100


---

Detects NetNTLM downgrade attack

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_net_ntlm_downgrade.yml))
```yaml
title: NetNTLM Downgrade Attack
id: d67572a0-e2ec-45d6-b8db-c100d14b8ef2
description: Detects NetNTLM downgrade attack
status: experimental
references:
    - https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
author: Florian Roth, wagga
date: 2018/03/20
modified: 2021/09/21
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains|all: 
            - 'SYSTEM\'
            - 'ControlSet'
            - '\Control\Lsa'
        TargetObject|endswith:
            - '\lmcompatibilitylevel'
            - '\NtlmMinClientSec'
            - '\RestrictSendingNTLMTraffic'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
