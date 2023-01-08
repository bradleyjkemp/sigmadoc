---
title: "Prefetch File Deletion"
aliases:
  - "/rule/0a1f9d29-6465-4776-b091-7f43b26e4c89"
ruleid: 0a1f9d29-6465-4776-b091-7f43b26e4c89

tags:
  - attack.defense_evasion
  - attack.t1070.004



status: experimental





date: Wed, 29 Sep 2021 09:42:17 +0200


---

Detects the deletion of a prefetch file (AntiForensic)

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_delete/file_delete_win_delete_prefetch.yml))
```yaml
title: Prefetch File Deletion
id: 0a1f9d29-6465-4776-b091-7f43b26e4c89 
status: experimental
description: Detects the deletion of a prefetch file (AntiForensic)
level: high
author: Cedric MAURUGEON
date: 2021/09/29
modified: 2022/01/15
tags:
    - attack.defense_evasion
    - attack.t1070.004
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\Prefetch\'
        TargetFilename|endswith: '.pf'
    exception:
        Image: 'C:\windows\system32\svchost.exe'
        User|startswith: 
            - 'NT AUTHORITY\SYSTEM'
            - 'AUTORITE NT\Sys' # French language settings
    condition: selection and not exception
falsepositives:
    - Unknown

```
