---
title: "Base64 Encoded Reflective Assembly Load"
aliases:
  - "/rule/62b7ccc9-23b4-471e-aa15-6da3663c4d59"


tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027



status: test





date: Wed, 2 Mar 2022 10:37:36 +0100


---

Detects base64 encoded .NET reflective loading of Assembly

<!--more-->


## Known false-positives

* Unlikely



## References

* https://github.com/Neo23x0/Raccine/blob/main/yara/mal_revil.yar


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_base64_reflective_assembly_load.yml))
```yaml
title: Base64 Encoded Reflective Assembly Load
id: 62b7ccc9-23b4-471e-aa15-6da3663c4d59
status: test
description: Detects base64 encoded .NET reflective loading of Assembly
author: Christian Burkard
date: 2022/03/01
modified: 2022/03/07
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
references:
    - https://github.com/Neo23x0/Raccine/blob/main/yara/mal_revil.yar
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    # [Reflection.Assembly]::Load(
    CommandLine|contains: 
      - 'WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA'
      - 'sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA'
      - 'bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Unlikely
level: high
```
