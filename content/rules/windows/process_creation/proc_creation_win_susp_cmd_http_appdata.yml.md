---
title: "Command Line Execution with Suspicious URL and AppData Strings"
aliases:
  - "/rule/1ac8666b-046f-4201-8aba-1951aaec03a3"


tags:
  - attack.execution
  - attack.t1059.003
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1105



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)

<!--more-->


## Known false-positives

* High



## References

* https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100
* https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_cmd_http_appdata.yml))
```yaml
title: Command Line Execution with Suspicious URL and AppData Strings
id: 1ac8666b-046f-4201-8aba-1951aaec03a3
status: test
description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)
author: Florian Roth, Jonhnathan Ribeiro, oscd.community
references:
  - https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100
  - https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - 'http'       # captures both http and https
      - '://'
      - '%AppData%'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - High
level: medium
tags:
  - attack.execution
  - attack.t1059.003
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1105

```