---
title: "Suspicious Rundll32 Script in CommandLine"
aliases:
  - "/rule/73fcad2e-ff14-4c38-b11d-4172c8ac86c7"


tags:
  - attack.defense_evasion
  - attack.t1218.011



status: experimental





date: Sat, 4 Dec 2021 20:32:42 +0100


---

Detects suspicious process related to rundll32 based on arguments

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_script_run.yml))
```yaml
title: Suspicious Rundll32 Script in CommandLine
id: 73fcad2e-ff14-4c38-b11d-4172c8ac86c7
status: experimental
description: Detects suspicious process related to rundll32 based on arguments
author: frack113
references:
  - https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md
date: 2021/12/04
logsource:
  category: process_creation
  product: windows
detection:
  selection_run:
    CommandLine|contains|all:
      - rundll32
      - 'mshtml,RunHTMLApplication'
  selection_script:
    CommandLine|contains:
      - 'javascript:'
      - 'vbscript:'
  condition: all of selection_*
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218.011 

```
