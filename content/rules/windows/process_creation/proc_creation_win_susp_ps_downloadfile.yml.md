---
title: "PowerShell DownloadFile"
aliases:
  - "/rule/8f70ac5f-1f6f-4f8e-b454-db19561216c5"
ruleid: 8f70ac5f-1f6f-4f8e-b454-db19561216c5

tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1104
  - attack.t1105



status: test





date: Wed, 25 Mar 2020 14:58:14 +0100


---

Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ps_downloadfile.yml))
```yaml
title: PowerShell DownloadFile
id: 8f70ac5f-1f6f-4f8e-b454-db19561216c5
status: test
description: Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line
author: Florian Roth
references:
  - https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html
date: 2020/08/28
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - '.DownloadFile'
      - 'System.Net.WebClient'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1104
  - attack.t1105

```
