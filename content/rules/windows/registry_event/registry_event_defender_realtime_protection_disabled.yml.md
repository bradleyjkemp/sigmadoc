---
title: "Windows Defender Real-Time Protection Disabled"
aliases:
  - "/rule/fd115e64-97c7-491f-951c-fc8da7e042fa"
ruleid: fd115e64-97c7-491f-951c-fc8da7e042fa

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Mon, 18 Oct 2021 10:07:44 +0400


---

Detects disabling Windows Defender Real-Time Protection by modifying registry

<!--more-->


## Known false-positives

* Administrator actions



## References

* https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
* https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_defender_realtime_protection_disabled.yml))
```yaml
title: Windows Defender Real-Time Protection Disabled
id: fd115e64-97c7-491f-951c-fc8da7e042fa
description: Detects disabling Windows Defender Real-Time Protection by modifying registry
date: 2021/10/18
author: AlertIQ
references:
    - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
    - https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105 
status: experimental
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: registry_event
detection:
    tamper_registry1:
        EventType: SetValue
        TargetObject: 
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection'
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection'
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring'
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable'
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet\DisableBlockAtFirstSeen'
        Details: 'DWORD (0x00000001)'
    tamper_registry2:
        EventType: SetValue
        TargetObject: 
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet\SpynetReporting'
          - 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet\SubmitSamplesConsent'
        Details: 'DWORD (0x00000000)'
    condition: tamper_registry1 or tamper_registry2
falsepositives:
    - Administrator actions
level: high
```