---
title: "Mimikatz Command Line"
aliases:
  - "/rule/a642964e-bead-4bed-8910-1bb4d63e3b4d"
ruleid: a642964e-bead-4bed-8910-1bb4d63e3b4d

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.005
  - attack.t1003.006



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Detection well-known mimikatz command line arguments

<!--more-->


## Known false-positives

* Legitimate Administrator using tool for password recovery



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
* https://tools.thehacker.recipes/mimikatz/modules


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml))
```yaml
title: Mimikatz Command Line
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
status: test
description: Detection well-known mimikatz command line arguments
author: Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://tools.thehacker.recipes/mimikatz/modules
date: 2019/10/22
modified: 2022/02/07
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.005
  - attack.t1003.006
logsource:
  category: process_creation
  product: windows
detection:
  selection_1:
    CommandLine|contains:
      - DumpCreds
      - invoke-mimikatz
  module_names:
    CommandLine|contains:
      - rpc
      - token
      - crypto
      - dpapi
      - sekurlsa
      - kerberos
      - lsadump
      - privilege
      - process
      - vault
  mimikatz_separator:
    CommandLine|contains:
      - '::'
  function_names: # To cover functions from modules that are not in module_names (likely too generic)
    CommandLine|contains:
      - 'aadcookie' #misc module
      - 'detours' #misc module
      - 'memssp' #misc module
      - 'mflt' #misc module
      - 'ncroutemon' #misc module
      - 'ngcsign' #misc module
      - 'printnightmare' #misc module
      - 'skeleton' #misc module
      - 'preshutdown'  #service module
      - 'mstsc'  #ts module
      - 'multirdp'  #ts module
  filter_1:
    CommandLine|contains:
      - 'function Convert-GuidToCompressedGuid'
  condition: ( selection_1 or (module_names and mimikatz_separator) or (function_names and mimikatz_separator) ) and not 1 of filter*
falsepositives:
  - Legitimate Administrator using tool for password recovery
level: medium

```
