---
title: "Run PowerShell Script from Redirected Input Stream"
aliases:
  - "/rule/c83bf4b5-cdf0-437c-90fa-43d734f7c476"


tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects PowerShell script execution via input stream redirect

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Powershell.yml
* https://twitter.com/Moriarty_Meng/status/984380793383370752


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_run_powershell_script_from_input_stream.yml))
```yaml
title: Run PowerShell Script from Redirected Input Stream
id: c83bf4b5-cdf0-437c-90fa-43d734f7c476
status: test
description: Detects PowerShell script execution via input stream redirect
author: Moriarty Meng (idea), Anton Kutepov (rule), oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Powershell.yml
  - https://twitter.com/Moriarty_Meng/status/984380793383370752
date: 2020/10/17
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  powershell_started:
    Image|endswith: '\powershell.exe'
  redirect_to_input_stream:
    CommandLine|re: '\s-\s*<'
  condition: powershell_started and redirect_to_input_stream
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059

```
