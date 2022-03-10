---
title: "Accessing Encrypted Credentials from Google Chrome Login Database"
aliases:
  - "/rule/98f4c75c-3089-44f3-b733-b327b9cd9c9d"


tags:
  - attack.credential_access
  - attack.t1555.003



status: deprecated





date: Mon, 20 Dec 2021 10:43:32 +0100


---

Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.
Web browsers typically store the credentials in an encrypted format within a credential store.


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_access_to_chrome_login_data.yml))
```yaml
title: Accessing Encrypted Credentials from Google Chrome Login Database
id: 98f4c75c-3089-44f3-b733-b327b9cd9c9d
status: deprecated
author: frack113
date: 2021/12/20
description: |
  Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
  Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.
  Web browsers typically store the credentials in an encrypted format within a credential store.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_cmd:
        ScriptBlockText|contains|all: 
            - Copy-Item
            - '-Destination'
    selection_path:
        ScriptBlockText|contains:
            - '\Google\Chrome\User Data\Default\Login Data'
            - '\Google\Chrome\User Data\Default\Login Data For Account'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
tags:
    - attack.credential_access
    - attack.t1555.003
```
