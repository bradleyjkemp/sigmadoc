---
title: "Powershell MsXml COM Object"
aliases:
  - "/rule/78aa1347-1517-4454-9982-b338d6df8343"


tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

Adversaries may abuse PowerShell commands and scripts for execution.
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell)
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code


<!--more-->


## Known false-positives

* legitimate administrative script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-7---powershell-msxml-com-object---with-prompt
* https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms766431(v=vs.85)


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_msxml_com.yml))
```yaml
title: Powershell MsXml COM Object
id: 78aa1347-1517-4454-9982-b338d6df8343
status: experimental
description: |
  Adversaries may abuse PowerShell commands and scripts for execution.
  PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell)
  Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code
author: frack113
date: 2022/01/19
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-7---powershell-msxml-com-object---with-prompt
    - https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms766431(v=vs.85)
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
            - New-Object
            - '-ComObject'
            - MsXml2.ServerXmlHttp
    condition: selection
falsepositives:
  - legitimate administrative script
level: medium
tags:
  - attack.execution
  - attack.t1059.001

```
