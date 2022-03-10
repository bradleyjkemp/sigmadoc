---
title: "GatherNetworkInfo.vbs Script Usage"
aliases:
  - "/rule/575dce0c-8139-4e30-9295-1ee75969f7fe"


tags:
  - attack.discovery
  - attack.group_policy_discovery
  - attack.execution
  - attack.command_and_scripting_interpreter
  - attack.visual_basic
  - attack.t1059.005



status: experimental





date: Mon, 3 Jan 2022 11:49:17 +1100


---

Adversaries can abuse of C:\Windows\System32\gatherNetworkInfo.vbs script along with cscript.exe to gather information about the target

<!--more-->


## Known false-positives

* Administrative activity



## References

* https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbin_cscript_gathernetworkinfo.yml))
```yaml
title: GatherNetworkInfo.vbs Script Usage
id: 575dce0c-8139-4e30-9295-1ee75969f7fe
description: Adversaries can abuse of C:\Windows\System32\gatherNetworkInfo.vbs script along with cscript.exe to gather information about the target
status: experimental
references:
    - https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs 
author: blueteamer8699
date: 2022/01/03
tags:
    - attack.discovery
    - attack.group_policy_discovery
    - attack.execution
    - attack.command_and_scripting_interpreter
    - attack.visual_basic
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'cscript.exe'
            - 'gatherNetworkInfo.vbs'
    condition: selection
falsepositives:
    - Administrative activity
fields:
    - CommandLine
    - ParentImage
level: medium

```
