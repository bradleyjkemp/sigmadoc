---
title: "Explorer Root Flag Process Tree Break"
aliases:
  - "/rule/949f1ffb-6e85-4f00-ae1e-c3c5b190d605"
ruleid: 949f1ffb-6e85-4f00-ae1e-c3c5b190d605

tags:
  - attack.defense_evasion
  - attack.t1036



status: test





date: Mon, 29 Jun 2020 12:07:15 +0200


---

Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer

<!--more-->


## Known false-positives

* Unknown how many legitimate software products use that method



## References

* https://twitter.com/CyberRaiju/status/1273597319322058752
* https://twitter.com/bohops/status/1276357235954909188?s=12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_explorer_break_proctree.yml))
```yaml
title: Explorer Root Flag Process Tree Break
id: 949f1ffb-6e85-4f00-ae1e-c3c5b190d605
status: test
description: Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer
author: Florian Roth
references:
  - https://twitter.com/CyberRaiju/status/1273597319322058752
  - https://twitter.com/bohops/status/1276357235954909188?s=12
date: 2019/06/29
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'explorer.exe'
      - ' /root,'
  condition: selection
falsepositives:
  - Unknown how many legitimate software products use that method
level: medium
tags:
  - attack.defense_evasion
  - attack.t1036

```
