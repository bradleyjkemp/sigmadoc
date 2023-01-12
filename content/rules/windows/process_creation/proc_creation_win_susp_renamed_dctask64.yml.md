---
title: "Renamed ZOHO Dctask64"
aliases:
  - "/rule/340a090b-c4e9-412e-bb36-b4b16fe96f9b"
ruleid: 340a090b-c4e9-412e-bb36-b4b16fe96f9b

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1055.001
  - attack.t1202
  - attack.t1218



status: test





date: Tue, 28 Jan 2020 11:29:24 +0100


---

Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation

<!--more-->


## Known false-positives

* Unknown yet



## References

* https://twitter.com/gN3mes1s/status/1222088214581825540
* https://twitter.com/gN3mes1s/status/1222095963789111296
* https://twitter.com/gN3mes1s/status/1222095371175911424


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_renamed_dctask64.yml))
```yaml
title: Renamed ZOHO Dctask64
id: 340a090b-c4e9-412e-bb36-b4b16fe96f9b
status: test
description: Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation
author: Florian Roth
references:
  - https://twitter.com/gN3mes1s/status/1222088214581825540
  - https://twitter.com/gN3mes1s/status/1222095963789111296
  - https://twitter.com/gN3mes1s/status/1222095371175911424
date: 2020/01/28
modified: 2021/12/08
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Hashes|contains: '6834B1B94E49701D77CCB3C0895E1AFD'
  filter:
    Image|endswith: '\dctask64.exe'
  condition: selection and not filter
fields:
  - CommandLine
  - ParentCommandLine
  - ParentImage
falsepositives:
  - Unknown yet
level: high
tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1055.001
  - attack.t1202
  - attack.t1218

```