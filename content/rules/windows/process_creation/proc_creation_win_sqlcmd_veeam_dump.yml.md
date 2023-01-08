---
title: "VeeamBackup Database Credentials Dump"
aliases:
  - "/rule/b57ba453-b384-4ab9-9f40-1038086b4e53"
ruleid: b57ba453-b384-4ab9-9f40-1038086b4e53

tags:
  - attack.collection
  - attack.t1005



status: experimental





date: Mon, 20 Dec 2021 18:59:11 +0100


---

Detects dump of credentials in VeeamBackup dbo

<!--more-->


## Known false-positives

* Unknown



## References

* https://thedfirreport.com/2021/12/13/diavol-ransomware/
* https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_dump.yml))
```yaml
title: VeeamBackup Database Credentials Dump
id: b57ba453-b384-4ab9-9f40-1038086b4e53
status: experimental
author: frack113
date: 2021/12/20
description: Detects dump of credentials in VeeamBackup dbo 
references:
   - https://thedfirreport.com/2021/12/13/diavol-ransomware/
   - https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith: '\sqlcmd.exe'
    selection_query:
        CommandLine|contains|all:
            - 'SELECT'
            - 'TOP'
            - '[VeeamBackup].[dbo].[Credentials]'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
