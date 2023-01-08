---
title: "Powershell XML Execute Command"
aliases:
  - "/rule/6c6c6282-7671-4fe9-a0ce-a2dcebdc342b"
ruleid: 6c6c6282-7671-4fe9-a0ce-a2dcebdc342b

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

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-8---powershell-xml-requests


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_xml_iex.yml))
```yaml
title: Powershell XML Execute Command
id: 6c6c6282-7671-4fe9-a0ce-a2dcebdc342b
status: experimental
description: |
  Adversaries may abuse PowerShell commands and scripts for execution.
  PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell)
  Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code
author: frack113
date: 2022/01/19
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-8---powershell-xml-requests
logsource:
    product: windows
    category: ps_script
detection:
    selection_xml:
        ScriptBlockText|contains|all:
            - New-Object
            - System.Xml.XmlDocument
            - .Load
    selection_exec:
            - IEX
            - Invoke-Expression
    condition: all of selection_*
falsepositives:
  - legitimate administrative script
level: medium
tags:
  - attack.execution
  - attack.t1059.001

```
