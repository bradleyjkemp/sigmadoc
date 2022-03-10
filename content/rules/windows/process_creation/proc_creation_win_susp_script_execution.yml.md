---
title: "WSF/JSE/JS/VBA/VBE File Execution"
aliases:
  - "/rule/1e33157c-53b1-41ad-bbcc-780b80b58288"


tags:
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious file execution by wscript and cscript

<!--more-->


## Known false-positives

* Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_script_execution.yml))
```yaml
title: WSF/JSE/JS/VBA/VBE File Execution
id: 1e33157c-53b1-41ad-bbcc-780b80b58288
status: test
description: Detects suspicious file execution by wscript and cscript
author: Michael Haag
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
    CommandLine|contains:
      - '.jse'
      - '.vbe'
      - '.js'
      - '.vba'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.
level: medium
tags:
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007
  

```
