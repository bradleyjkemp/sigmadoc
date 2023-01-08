---
title: "Persistent Outlook Landing Pages"
aliases:
  - "/rule/ddd171b5-2cc6-4975-9e78-f0eccd08cc76"
ruleid: ddd171b5-2cc6-4975-9e78-f0eccd08cc76

tags:
  - attack.persistence
  - attack.t1112



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the manipulation of persistent URLs which can be malicious

<!--more-->


## Known false-positives

* unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=70
* https://support.microsoft.com/en-us/topic/outlook-home-page-feature-is-missing-in-folder-properties-d207edb7-aa02-46c5-b608-5d9dbed9bd04?ui=en-us&rs=en-us&ad=us


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_outlook_registry_webview.yml))
```yaml
title: Persistent Outlook Landing Pages
id: ddd171b5-2cc6-4975-9e78-f0eccd08cc76
description: Detects the manipulation of persistent URLs which can be malicious
status: experimental
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=70
  - https://support.microsoft.com/en-us/topic/outlook-home-page-feature-is-missing-in-folder-properties-d207edb7-aa02-46c5-b608-5d9dbed9bd04?ui=en-us&rs=en-us&ad=us
author: Tobias Michalski
date: 2021/06/09
modified: 2022/02/09
tags:
  - attack.persistence
  - attack.t1112
logsource:
  product: windows
  category: registry_event
detection:
  selection1:
    TargetObject|contains: 
      - '\Software\Microsoft\Office\'
      - '\Outlook\WebView\'
    TargetObject|endswith: '\URL'
  selection2:
    TargetObject|contains: 
      - '\Calendar\'
      - '\Inbox\'
  condition: selection1 and selection2
fields:
  - Details
falsepositives:
  - unknown
level: high

```
