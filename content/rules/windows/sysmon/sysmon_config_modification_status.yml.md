---
title: "Sysmon Configuration Modification"
aliases:
  - "/rule/1f2b5353-573f-4880-8e33-7d04dcf97744"


tags:
  - attack.defense_evasion
  - attack.t1564



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Someone try to hide from Sysmon

<!--more-->


## Known false-positives

* legitimate administrative action



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
* https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/sysmon/sysmon_config_modification_status.yml))
```yaml
title: Sysmon Configuration Modification
id: 1f2b5353-573f-4880-8e33-7d04dcf97744
description: Someone try to hide from Sysmon
status: experimental
author: frack113
date: 2021/06/04
modified: 2021/09/07
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
    - https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html
tags:
    - attack.defense_evasion
    - attack.t1564
logsource:
    product: windows
    category: sysmon_status
detection:
    selection_stop:
        State: Stopped
    selection_conf:
        - 'Sysmon config state changed'
    condition: selection_stop or selection_conf
falsepositives:
    - legitimate administrative action
level: high  

```
