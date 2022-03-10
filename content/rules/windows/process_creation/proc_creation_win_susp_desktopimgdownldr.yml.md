---
title: "Suspicious Desktopimgdownldr Command"
aliases:
  - "/rule/bb58aa4a-b80b-415a-a2c0-2f65a4c81009"


tags:
  - attack.command_and_control
  - attack.t1105



status: test





date: Fri, 3 Jul 2020 09:45:48 +0200


---

Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
* https://twitter.com/SBousseaden/status/1278977301745741825


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_desktopimgdownldr.yml))
```yaml
title: Suspicious Desktopimgdownldr Command
id: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
status: test
description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
author: Florian Roth
references:
  - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
  - https://twitter.com/SBousseaden/status/1278977301745741825
date: 2020/07/03
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains: ' /lockscreenurl:'
  selection1_filter:
    CommandLine|contains:
      - '.jpg'
      - '.jpeg'
      - '.png'
  selection_reg:
    CommandLine|contains|all:
      - 'reg delete'
      - '\PersonalizationCSP'
  condition: ( selection1 and not selection1_filter ) or selection_reg
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: high
tags:
  - attack.command_and_control
  - attack.t1105

```