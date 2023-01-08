---
title: "Netsh Port or Application Allowed"
aliases:
  - "/rule/cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c"
ruleid: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c

tags:
  - attack.defense_evasion
  - attack.t1562.004



status: test





date: Mon, 1 Apr 2019 08:16:56 +0200


---

Allow Incoming Connections by Port or Application on Windows Firewall

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_netsh_fw_add.yml))
```yaml
title: Netsh Port or Application Allowed
id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
status: test
description: Allow Incoming Connections by Port or Application on Windows Firewall
author: Markus Neis, Sander Wiebing
references:
  - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
  - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
modified: 2022/02/10
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|endswith: '\netsh.exe'
  selection2:
    CommandLine|contains|all:
      - 'firewall'
      - 'add'
  filter_dropbox:
    CommandLine|contains:
      - '\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow "program=C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
      - '\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow "program=C:\Program Files\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
  condition: selection1 and selection2 and not 1 of filter_*
falsepositives:
  - Legitimate administration
level: medium
tags:
  - attack.defense_evasion
  - attack.t1562.004

```
