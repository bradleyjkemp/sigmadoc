---
title: "Credentials from Password Stores - Keychain"
aliases:
  - "/rule/b120b587-a4c2-4b94-875d-99c9807d6955"


tags:
  - attack.credential_access
  - attack.t1555.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects passwords dumps from Keychain

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.001/T1555.001.md
* https://gist.github.com/Capybara/6228955


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_creds_from_keychain.yml))
```yaml
title: Credentials from Password Stores - Keychain
id: b120b587-a4c2-4b94-875d-99c9807d6955
status: test
description: Detects passwords dumps from Keychain
author: Tim Ismilyaev, oscd.community, Florian Roth
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.001/T1555.001.md
  - https://gist.github.com/Capybara/6228955
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection1:
    Image: '/usr/bin/security'
    CommandLine|contains:
      - 'find-certificate'
      - ' export '
  selection2:
    CommandLine|contains:
      - ' dump-keychain '
      - ' login-keychain '
  condition: 1 of selection*
falsepositives:
  - Legitimate administration activities
level: medium
tags:
  - attack.credential_access
  - attack.t1555.001

```
