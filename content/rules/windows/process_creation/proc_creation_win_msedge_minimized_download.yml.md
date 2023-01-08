---
title: "Suspicious Minimized MSEdge Start"
aliases:
  - "/rule/94771a71-ba41-4b6e-a757-b531372eaab6"
ruleid: 94771a71-ba41-4b6e-a757-b531372eaab6

tags:
  - attack.command_and_control
  - attack.t1105







date: Wed, 12 Jan 2022 11:32:12 +0100


---

Detects the suspicious minimized start of MsEdge browser, which can be used to download files from the Internet

<!--more-->


## Known false-positives

* Software that uses MsEdge to download components in the background (see ParentImage, ParentCommandLine)



## References

* https://twitter.com/mrd0x/status/1478234484881436672?s=12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_msedge_minimized_download.yml))
```yaml
title: Suspicious Minimized MSEdge Start
id: 94771a71-ba41-4b6e-a757-b531372eaab6
description: Detects the suspicious minimized start of MsEdge browser, which can be used to download files from the Internet
author: Florian Roth
date: 2022/01/11
references:
  - https://twitter.com/mrd0x/status/1478234484881436672?s=12
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'start /min msedge'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Software that uses MsEdge to download components in the background (see ParentImage, ParentCommandLine)
level: high

```
