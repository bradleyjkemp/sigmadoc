---
title: "Remove Exported Mailbox from Exchange Webserver"
aliases:
  - "/rule/09570ae5-889e-43ea-aac0-0e1221fb3d95"
ruleid: 09570ae5-889e-43ea-aac0-0e1221fb3d95

tags:
  - attack.defense_evasion
  - attack.t1070



status: experimental





date: Tue, 31 Aug 2021 12:51:16 +0200


---

Detects removal of an exported Exchange mailbox which could be to cover tracks from ProxyShell exploit

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/exchange_proxyshell_rce.rb#L430


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/msexchange/win_exchange_proxyshell_remove_mailbox_export.yml))
```yaml
title: Remove Exported Mailbox from Exchange Webserver
id: 09570ae5-889e-43ea-aac0-0e1221fb3d95
status: experimental
description: Detects removal of an exported Exchange mailbox which could be to cover tracks from ProxyShell exploit
references:
    - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/exchange_proxyshell_rce.rb#L430
author: Christian Burkard
date: 2021/08/27
logsource:        
    service: msexchange-management
    product: windows
detection:
    command: 
        - 'Remove-MailboxExportRequest'
        - ' -Identity '
        - ' -Confirm "False"'
    condition: all of command
falsepositives:
    - unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1070

```
