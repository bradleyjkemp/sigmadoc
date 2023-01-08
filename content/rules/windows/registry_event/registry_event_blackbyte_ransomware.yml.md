---
title: "Blackbyte Ransomware Registry"
aliases:
  - "/rule/83314318-052a-4c90-a1ad-660ece38d276"
ruleid: 83314318-052a-4c90-a1ad-660ece38d276

tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental





date: Mon, 24 Jan 2022 10:03:52 +0100


---

BlackByte set three different registry values to escalate privileges and begin setting the stage for lateral movement and encryption

<!--more-->


## Known false-positives

* Unknown



## References

* https://redcanary.com/blog/blackbyte-ransomware/?utm_source=twitter&utm_medium=social
* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/blackbyte-ransomware-pt-1-in-depth-analysis/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_blackbyte_ransomware.yml))
```yaml
title: Blackbyte Ransomware Registry
id: 83314318-052a-4c90-a1ad-660ece38d276
description: BlackByte set three different registry values to escalate privileges and begin setting the stage for lateral movement and encryption
author: frack113
date: 2022/01/24
status: experimental
references:
    - https://redcanary.com/blog/blackbyte-ransomware/?utm_source=twitter&utm_medium=social
    - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/blackbyte-ransomware-pt-1-in-depth-analysis/
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject: 
            - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
            - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections
            - HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled 
        Details: DWORD (0x00000001)
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1112

```
