---
title: "Terminal Server Client Connection History Cleared"
aliases:
  - "/rule/07bdd2f5-9c58-4f38-aec8-e101bb79ef8d"


tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1112



status: experimental





date: Tue, 19 Oct 2021 18:30:02 +0200


---

Detects the deletion of registry keys containing the MSTSC connection history

<!--more-->


## Known false-positives

* unknown



## References

* https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer
* http://woshub.com/how-to-clear-rdp-connections-history/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_mstsc_history_cleared.yml))
```yaml
title: Terminal Server Client Connection History Cleared
id: 07bdd2f5-9c58-4f38-aec8-e101bb79ef8d
description: Detects the deletion of registry keys containing the MSTSC connection history
references:
    - https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer
    - http://woshub.com/how-to-clear-rdp-connections-history/
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1112
author: Christian Burkard
status: experimental
date: 2021/10/19
logsource:
    category: registry_event
    product: windows
detection:
    selection1:
        EventType: DeleteValue
        TargetObject|contains: '\Microsoft\Terminal Server Client\Default\MRU'
    selection2:
        EventType: DeleteKey
        TargetObject|contains: '\Microsoft\Terminal Server Client\Servers\'
    condition: 1 of selection*
falsepositives:
    - unknown
level: high

```
