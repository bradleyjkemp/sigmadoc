---
title: "Redirect Output in CommandLine"
aliases:
  - "/rule/4f4eaa9f-5ad4-410c-a4be-bc6132b0175a"


tags:
  - attack.discovery
  - attack.t1082



status: experimental





date: Sun, 23 Jan 2022 11:37:01 +0100


---

Use ">" to redicrect information in commandline

<!--more-->


## Known false-positives

* Unknown



## References

* https://ss64.com/nt/syntax-redirection.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cmd_redirect.yml))
```yaml
title: Redirect Output in CommandLine
id: 4f4eaa9f-5ad4-410c-a4be-bc6132b0175a
status: experimental
description: Use ">" to redicrect information in commandline
author: frack113
references:
    - https://ss64.com/nt/syntax-redirection.html
date: 2022/01/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: '>'
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1082

```
