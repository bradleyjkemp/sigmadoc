---
title: "Use IE Registry for Persistence"
aliases:
  - "/rule/d88d0ab2-e696-4d40-a2ed-9790064e66b3"


tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental





date: Fri, 28 Jan 2022 16:12:38 +0100


---

Use IE registry to hide a scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md#atomic-test-5---javascript-in-registry


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_ie_persistence.yml))
```yaml
title: Use IE Registry for Persistence
id: d88d0ab2-e696-4d40-a2ed-9790064e66b3
description: Use IE registry to hide a scripts
author: frack113
date: 2022/01/22
modified: 2022/02/20
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md#atomic-test-5---javascript-in-registry
logsource:
    category: registry_event
    product: windows
detection:
    selection_domains:
        EventType: SetValue
        TargetObject|contains: \Software\Microsoft\Windows\CurrentVersion\Internet Settings
    filter_dword:
        Details|startswith: DWORD
    filter_office:
        Details:
            - 'Cookie:'
            - 'Visited:'
            - '(Empty)'
    filter_binary:
        Details: 'Binary Data'
    condition: selection_domains and not 1 of filter_*
falsepositives:
    - Unknown
level: low # as unknow false positives
tags:
  - attack.defense_evasion
  - attack.t1112

```
