---
title: "CrackMapExec Command Line Flags"
aliases:
  - "/rule/42a993dd-bb3e-48c8-b372-4d6684c4106c"




status: experimental





date: Fri, 25 Feb 2022 11:39:19 +0100


---

This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.

<!--more-->


## Known false-positives

* Unknown



## References

* https://mpgn.gitbook.io/crackmapexec/smb-protocol/authentication/checking-credentials-local
* https://www.mandiant.com/resources/telegram-malware-iranian-espionage
* https://www.infosecmatter.com/crackmapexec-module-library/?cmem=mssql-mimikatz
* https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-pe_inject


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_crackmapexec_flags.yml))
```yaml
title: CrackMapExec Command Line Flags
id: 42a993dd-bb3e-48c8-b372-4d6684c4106c
status: experimental
description: This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.
author: Florian Roth
references:
  - https://mpgn.gitbook.io/crackmapexec/smb-protocol/authentication/checking-credentials-local
  - https://www.mandiant.com/resources/telegram-malware-iranian-espionage
  - https://www.infosecmatter.com/crackmapexec-module-library/?cmem=mssql-mimikatz
  - https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-pe_inject
date: 2022/02/25
logsource:
  category: process_creation
  product: windows
detection:
  selection_special:
    CommandLine|contains:
      - ' -M pe_inject '
  selection_execute:
    CommandLine|contains|all:
      - ' --local-auth'
      - ' -u '
      - ' -x '
  selection_hash:
    CommandLine|contains|all:
      - ' --local-auth'
      - ' -u '
      - ' -p '
      - " -H 'NTHASH'"
  selection_module_mssql:
    CommandLine|contains|all:
      - ' mssql '
      - ' -u '
      - ' -p '
      - ' -M '
      - ' -d '
  selection_module_smb1:
    CommandLine|contains|all:
      - ' smb '
      - ' -u '
      - ' -H '
      - ' -M '
      - ' -o '
  selection_module_smb2:
    CommandLine|contains|all:
      - ' smb '
      - ' -u '
      - ' -p '
      - ' --local-auth'
  part_localauth_1:
    CommandLine|contains|all:
      - ' --local-auth'
      - ' -u '
      - ' -p '
  part_localauth_2:
    CommandLine|contains|all:
      - ' 10.'
      - ' 192.168.'
      - '/24 '
  condition: 1 of selection* or all of part_localauth*
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Unknown
level: high

```