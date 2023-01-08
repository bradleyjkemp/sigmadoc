---
title: "Suspicious Execution of Powershell with Base64"
aliases:
  - "/rule/fb843269-508c-4b76-8b8d-88679db22ce7"
ruleid: fb843269-508c-4b76-8b8d-88679db22ce7

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sun, 2 Jan 2022 10:36:52 +0100


---

Commandline to lauch powershell with a base64 payload

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets
* https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
* https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_powershell_encode.yml))
```yaml
title: Suspicious Execution of Powershell with Base64 
id: fb843269-508c-4b76-8b8d-88679db22ce7
status: experimental
description: Commandline to lauch powershell with a base64 payload 
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets
    - https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
    - https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/
date: 2022/01/02
modified: 2022/02/10
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \powershell.exe
        CommandLine|contains:
            - ' -e '
            - ' -en '
            - ' -enc '
            - ' -enco'
            - ' -ec '
    filter:
        CommandLine|contains:
            - ' -Encoding '
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
tags:
    - attack.execution
    - attack.t1059.001

```
