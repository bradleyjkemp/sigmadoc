---
title: "Clearing Windows Console History"
aliases:
  - "/rule/bde47d4b-9987-405c-94c7-b080410e8ea7"
ruleid: bde47d4b-9987-405c-94c7-b080410e8ea7

tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1070.003



status: experimental





date: Thu, 25 Nov 2021 19:04:30 -0600


---

Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.

<!--more-->


## Known false-positives

* Unknown



## References

* https://stefanos.cloud/blog/kb/how-to-clear-the-powershell-command-history/
* https://www.shellhacks.com/clear-history-powershell/
* https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml))
```yaml
title: Clearing Windows Console History
id: bde47d4b-9987-405c-94c7-b080410e8ea7
description: Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
status: experimental
author: Austin Songer @austinsonger
date: 2021/11/25
references:
    - https://stefanos.cloud/blog/kb/how-to-clear-the-powershell-command-history/
    - https://www.shellhacks.com/clear-history-powershell/
    - https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics
logsource:
      product: windows
      category: ps_script
detection: 
    selection1:
        ScriptBlockText|contains:
            - Clear-History
    selection2a:
        ScriptBlockText|contains:
            - Remove-Item
            - rm
    selection2b:
        ScriptBlockText|contains:
            - ConsoleHost_history.txt
            - (Get-PSReadlineOption).HistorySavePath
    condition: selection1 or selection2a and selection2b
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1070.003
level: high
falsepositives:
    - Unknown

```
