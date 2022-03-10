---
title: "NTFS Alternate Data Stream"
aliases:
  - "/rule/8c521530-5169-495d-a199-0a3a881ad24e"


tags:
  - attack.defense_evasion
  - attack.t1564.004
  - attack.execution
  - attack.t1059.001



status: experimental





date: Tue, 24 Jul 2018 19:49:08 +0200


---

Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.

<!--more-->


## Known false-positives

* unknown



## References

* http://www.powertheshell.com/ntfsstreams/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_ntfs_ads_access.yml))
```yaml
title: NTFS Alternate Data Stream
id: 8c521530-5169-495d-a199-0a3a881ad24e
status: experimental
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
references:
    - http://www.powertheshell.com/ntfsstreams/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md
tags:
    - attack.defense_evasion
    - attack.t1564.004
    - attack.execution
    - attack.t1059.001
author: Sami Ruohonen
date: 2018/07/24
modified: 2021/12/02
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_content:
        ScriptBlockText|contains:
            - set-content
            - add-content
    selection_stream:
        ScriptBlockText|contains: '-stream'
    condition: all of selection*
falsepositives:
    - unknown
level: high

```
