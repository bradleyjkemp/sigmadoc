---
title: "Suspicious PsExec Execution - Zeek"
aliases:
  - "/rule/f1b3a22a-45e6-4004-afb5-4291f9c21166"

tags:
  - attack.lateral_movement
  - attack.t1077
  - attack.t1021.002





level: high



date: Sat, 2 May 2020 07:27:51 -0400


---

detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

<!--more-->


## Known false-positives

* nothing observed so far



## References

* https://github.com/neo23x0/sigma/blob/d42e87edd741dd646db946f30964f331f92f50e6/rules/windows/builtin/win_susp_psexec.yml


## Raw rule
```yaml
title: Suspicious PsExec Execution - Zeek
id: f1b3a22a-45e6-4004-afb5-4291f9c21166
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: 'Samir Bousseaden, @neu5ron'
date: 2020/04/02
references:
    - https://github.com/neo23x0/sigma/blob/d42e87edd741dd646db946f30964f331f92f50e6/rules/windows/builtin/win_susp_psexec.yml
tags:
    - attack.lateral_movement
    - attack.t1077 # an old one
    - attack.t1021.002
logsource:
    product: zeek
    service: smb_files
detection:
    selection1:
        path: \\*\IPC$
        name:
            - '*-stdin'
            - '*-stdout'
            - '*-stderr'
    selection2:
        name: \\*\IPC$
        path: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives:
    - nothing observed so far
level: high

```
