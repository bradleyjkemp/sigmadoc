---
title: "Suspicious ZipExec Execution"
aliases:
  - "/rule/90dcf730-1b71-4ae7-9ffc-6fcf62bd0132"


tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218
  - attack.t1202



status: experimental





date: Sun, 7 Nov 2021 21:57:40 +0100


---

ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1451237393017839616
* https://github.com/Tylous/ZipExec


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_zipexec.yml))
```yaml
title: Suspicious ZipExec Execution
id: 90dcf730-1b71-4ae7-9ffc-6fcf62bd0132
status: experimental
description: ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.
references:
    - https://twitter.com/SBousseaden/status/1451237393017839616
    - https://github.com/Tylous/ZipExec
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218
    - attack.t1202
author: frack113
date: 2021/11/07
logsource:
    category: process_creation
    product: windows
detection:
    run:
        CommandLine|contains|all:
            - '/generic:Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
            - '/pass:'
            - '/user:'
    delete:
        CommandLine|contains|all:
            - '/delete'
            - 'Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
    condition: run or delete
falsepositives:
    - unknown
level: medium

```
