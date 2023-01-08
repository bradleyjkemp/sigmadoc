---
title: "Bypass UAC Using Event Viewer"
aliases:
  - "/rule/674202d0-b22a-4af4-ae5f-2eda1f3da1af"
ruleid: 674202d0-b22a-4af4-ae5f-2eda1f3da1af

tags:
  - attack.persistence
  - attack.t1547.010



status: experimental





date: Wed, 5 Jan 2022 19:52:52 +0100


---

Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification

<!--more-->


## Known false-positives

* Unknown



## References

* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-1---bypass-uac-using-event-viewer-cmd


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_bypass_uac_using_eventviewer.yml))
```yaml
title: Bypass UAC Using Event Viewer
id: 674202d0-b22a-4af4-ae5f-2eda1f3da1af
description: Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification
author: frack113
date: 2022/01/05
status: experimental
references:
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-1---bypass-uac-using-event-viewer-cmd
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|endswith: '_Classes\mscfile\shell\open\command\(Default)'
    filter:    
        Details: '%SystemRoot%\system32\mmc.exe "%1" %*'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
tags:
  - attack.persistence
  - attack.t1547.010

```
