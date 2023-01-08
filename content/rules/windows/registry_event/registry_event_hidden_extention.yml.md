---
title: "Registry Modification to Hidden File Extension"
aliases:
  - "/rule/5df86130-4e95-4a54-90f7-26541b40aec2"
ruleid: 5df86130-4e95-4a54-90f7-26541b40aec2

tags:
  - attack.persistence
  - attack.t1137



status: experimental





date: Sun, 23 Jan 2022 11:37:01 +0100


---

Hides the file extension through modification of the registry

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md#atomic-test-1---modify-registry-of-current-user-profile---cmd
* https://unit42.paloaltonetworks.com/ransomware-families/
* https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=TrojanSpy%3aMSIL%2fHakey.A


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_hidden_extention.yml))
```yaml
title: Registry Modification to Hidden File Extension
id: 5df86130-4e95-4a54-90f7-26541b40aec2
description: Hides the file extension through modification of the registry
author: frack113
date: 2022/01/22
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md#atomic-test-1---modify-registry-of-current-user-profile---cmd
    - https://unit42.paloaltonetworks.com/ransomware-families/
    - https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=TrojanSpy%3aMSIL%2fHakey.A
logsource:
    category: registry_event
    product: windows
detection:
    selection_HideFileExt:
        EventType: SetValue
        TargetObject|endswith: \SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt
        Details: DWORD (0x00000001)
    selection_Hidden:
        EventType: SetValue
        TargetObject|endswith: \SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden
        Details: DWORD (0x00000002)
    condition: 1 of selection_*
falsepositives:
    - Administrative scripts
level: medium
tags:
  - attack.persistence
  - attack.t1137

```
