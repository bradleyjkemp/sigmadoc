---
title: "Suspicious Windows Update Agent Empty Cmdline"
aliases:
  - "/rule/52d097e2-063e-4c9c-8fbb-855c8948d135"
ruleid: 52d097e2-063e-4c9c-8fbb-855c8948d135



status: experimental





date: Fri, 25 Feb 2022 16:02:42 +0100


---

Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags

<!--more-->


## Known false-positives

* Unknown



## References

* https://redcanary.com/blog/blackbyte-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_wuauclt_cmdline.yml))
```yaml
title: Suspicious Windows Update Agent Empty Cmdline
id: 52d097e2-063e-4c9c-8fbb-855c8948d135
status: experimental
description: Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
author: Florian Roth
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
date: 2022/02/26
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Wuauclt.exe'
        CommandLine|endswith: '\Wuauclt.exe' 
    condition: selection
falsepositives:
    - Unknown
level: high

```
