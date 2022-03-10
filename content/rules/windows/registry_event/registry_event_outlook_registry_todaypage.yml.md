---
title: "Persistent Outlook Landing Pages"
aliases:
  - "/rule/487bb375-12ef-41f6-baae-c6a1572b4dd1"


tags:
  - attack.persistence
  - attack.t1112



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the manipulation of persistent URLs which could execute malicious code

<!--more-->


## Known false-positives

* unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=70


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_outlook_registry_todaypage.yml))
```yaml
title: Persistent Outlook Landing Pages
id: 487bb375-12ef-41f6-baae-c6a1572b4dd1
description: Detects the manipulation of persistent URLs which could execute malicious code
status: experimental
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=70
author: Tobias Michalski
date: 2021/06/10
modified: 2022/03/05
tags:
  - attack.persistence
  - attack.t1112
logsource:
  product: windows
  category: registry_event
detection:
  selection1:
    TargetObject|contains: 
      - 'Software\Microsoft\Office\'
      - '\Outlook\Today\'
  selectionStamp:
    EventType: SetValue 
    TargetObject|endswith: Stamp
    Details: DWORD (0x00000001) 
  selectionUserDefined:
    TargetObject|endswith: UserDefinedUrl
  filter_office:
    Image|startswith: 
      - 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\'
      - 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\'
    Image|endswith: '\OfficeClickToRun.exe'
  condition: selection1 and (selectionStamp or selectionUserDefined) and not 1 of filter_*
fields:
  - Details
falsepositives:
  - unknown
level: high

```
