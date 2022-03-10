---
title: "Password Provided In Command Line Of Net.exe"
aliases:
  - "/rule/d4498716-1d52-438f-8084-4a603157d131"




status: experimental





date: Thu, 9 Dec 2021 20:33:37 +0000


---

Detects a when net.exe is called with a password in the command line

<!--more-->


## Known false-positives

* Unknown



## References

* Internal Research


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_net_use_password_plaintext.yml))
```yaml
title: Password Provided In Command Line Of Net.exe
id: d4498716-1d52-438f-8084-4a603157d131
status: experimental
description: Detects a when net.exe is called with a password in the command line
references:
    - Internal Research
author: Tim Shelton (HAWK.IO)
date: 2021/12/09
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: C:\Windows\System32\net.exe
    selection2:
        CommandLine|contains|all: 
            - 'net'
            - ' use '
            - ':*\\'
            - '/USER:* *'
    filter:
        CommandLine|endswith: ' '
    condition: all of selection* and not 1 of filter*
falsepositives:
    - Unknown
level: medium

```
