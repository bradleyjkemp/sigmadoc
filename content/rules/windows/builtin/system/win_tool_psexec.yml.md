---
title: "PsExec Tool Execution"
aliases:
  - "/rule/42c575ea-e41e-41f1-b248-8093c3e82a28"
ruleid: 42c575ea-e41e-41f1-b248-8093c3e82a28

tags:
  - attack.execution
  - attack.t1569.002
  - attack.s0029



status: experimental





date: Mon, 12 Jun 2017 23:57:06 +0200


---

Detects PsExec service installation and execution events (service and Sysmon)

<!--more-->


## Known false-positives

* unknown



## References

* https://www.jpcert.or.jp/english/pub/sr/ir_research.html
* https://jpcertcc.github.io/ToolAnalysisResultSheet


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_tool_psexec.yml))
```yaml
title: PsExec Tool Execution
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: experimental
description: Detects PsExec service installation and execution events (service and Sysmon)
author: Thomas Patzke
date: 2017/06/12
modified: 2021/09/21
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - ServiceName
    - ServiceFileName
    - TargetFilename
    - PipeName
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'PSEXESVC'
        ServiceFileName|endswith: '\PSEXESVC.exe'
    service_execution:
        EventID: 7036
        ServiceName: 'PSEXESVC'
    condition: service_installation or service_execution
falsepositives:
    - unknown
level: low
```
