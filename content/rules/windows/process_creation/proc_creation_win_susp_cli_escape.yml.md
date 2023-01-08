---
title: "Suspicious Commandline Escape"
aliases:
  - "/rule/f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd"
ruleid: f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd

tags:
  - attack.defense_evasion
  - attack.t1140



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious process that use escape characters

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://twitter.com/vysecurity/status/885545634958385153
* https://twitter.com/Hexacorn/status/885553465417756673
* https://twitter.com/Hexacorn/status/885570278637678592
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html
* http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_cli_escape.yml))
```yaml
title: Suspicious Commandline Escape
id: f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd
status: test
description: Detects suspicious process that use escape characters
author: juju4
references:
  - https://twitter.com/vysecurity/status/885545634958385153
  - https://twitter.com/Hexacorn/status/885553465417756673
  - https://twitter.com/Hexacorn/status/885570278637678592
  - https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html
  - http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/
date: 2018/12/11
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
            # - <TAB>   # no TAB modifier in sigmac yet, so this matches <TAB> (or TAB in elasticsearch backends without DSL queries)
      - 'h^t^t^p'
      - 'h"t"t"p'
  condition: selection
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: low
tags:
  - attack.defense_evasion
  - attack.t1140

```
