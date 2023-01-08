---
title: "Disable Administrative Share Creation at Startup"
aliases:
  - "/rule/c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e"
ruleid: c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e

tags:
  - attack.defense_evasion
  - attack.t1070.005



status: experimental





date: Sun, 16 Jan 2022 14:47:56 +0100


---

Administrative shares are hidden network shares created by Microsoft’s Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md#atomic-test-4---disable-administrative-share-creation-at-startup


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_disable_administrative_share.yml))
```yaml
title: Disable Administrative Share Creation at Startup
id: c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e
description: Administrative shares are hidden network shares created by Microsoft’s Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system
author: frack113
date: 2022/01/16
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md#atomic-test-4---disable-administrative-share-creation-at-startup
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|startswith: HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\
        TargetObject|endswith: 
            - AutoShareWks
            - AutoShareServer
        Details: DWORD (0x00000000)
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.005

```
