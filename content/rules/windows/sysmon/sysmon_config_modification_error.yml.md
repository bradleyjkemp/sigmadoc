---
title: "Sysmon Configuration Error"
aliases:
  - "/rule/815cd91b-7dbc-4247-841a-d7dd1392b0a8"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/sysmon/sysmon_config_modification_error.yml))
```yaml
title: Sysmon Configuration Error
id: 815cd91b-7dbc-4247-841a-d7dd1392b0a8
description: Someone try to hide from Sysmon
status: experimental
author: frack113
date: 2021/06/04
modified: 2022/02/09
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
    - https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html
tags:
    - attack.defense_evasion
    - attack.t1564
logsource:
    product: windows
    category: sysmon_error
detection:
    selection_error:
        Description|contains:
            - 'Failed to open service configuration with error'
            - 'Failed to connect to the driver to update configuration'
    selection_filter:
        Description|contains|all:
            - 'Failed to open service configuration with error'
            - 'Last error: The media is write protected.'
    condition: selection_error and not selection_filter
falsepositives:
    - legitimate administrative action
level: high 

```
