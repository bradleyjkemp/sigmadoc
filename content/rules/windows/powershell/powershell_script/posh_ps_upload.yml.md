---
title: "Windows PowerShell Upload Web Request"
aliases:
  - "/rule/d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb"
ruleid: d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb

tags:
  - attack.exfiltration
  - attack.t1020



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

Detects the use of various web request POST or PUT methods (including aliases) via Windows PowerShell command

<!--more-->


## Known false-positives

* legitim script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md
* https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_upload.yml))
```yaml
title: Windows PowerShell Upload Web Request
id: d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb
status: experimental
description: Detects the use of various web request POST or PUT methods (including aliases) via Windows PowerShell command
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md
    - https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2
author: frack113
date: 2022/01/07
logsource:
    product: windows
    category: ps_script
    definition: 'Script block logging must be enabled'
detection:
    selection_cmdlet:
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
    selection_method:
        ScriptBlockText|contains: '-Method '
    selection_verb:
            - ' Put ' 
            - ' Post '
    condition: all of selection_*
falsepositives:
    - legitim script
level: medium
tags:
    - attack.exfiltration
    - attack.t1020 

```
