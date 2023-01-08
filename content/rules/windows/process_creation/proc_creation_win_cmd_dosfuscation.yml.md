---
title: "Suspicious Dosfuscation Character in Commandline"
aliases:
  - "/rule/a77c1610-fc73-4019-8e29-0f51efc04a51"
ruleid: a77c1610-fc73-4019-8e29-0f51efc04a51

tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Tue, 15 Feb 2022 17:58:39 +0100


---

Posssible Payload Obfuscation

<!--more-->


## Known false-positives

* legitimate use



## References

* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cmd_dosfuscation.yml))
```yaml
title: Suspicious Dosfuscation Character in Commandline
id: a77c1610-fc73-4019-8e29-0f51efc04a51
status: experimental
description: Posssible Payload Obfuscation
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
author: frack113
date: 2022/02/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '^^'
            # - '""'
            - ',;,'
            - '%COMSPEC:~'
            # - '%%'
            # - '&&'
            - ' s^et '
            - ' s^e^t '
            - ' se^t '
    condition: selection
falsepositives:
    - legitimate use
level: medium
tags:
    - attack.execution
    - attack.t1059

```
