---
title: "Mimikatz MemSSP Default Log File Creation"
aliases:
  - "/rule/034affe8-6170-11ec-844f-0f78aa0c4d66"
ruleid: 034affe8-6170-11ec-844f-0f78aa0c4d66

tags:
  - attack.credential_access
  - attack.t1003



status: experimental





date: Mon, 20 Dec 2021 10:49:18 +0100


---

Detects Mimikatz MemSSP default log file creation

<!--more-->


## Known false-positives

* Unlikely



## References

* https://pentestlab.blog/2019/10/21/persistence-security-support-provider/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_mimimaktz_memssp_log_file.yml))
```yaml
title: Mimikatz MemSSP Default Log File Creation
id: 034affe8-6170-11ec-844f-0f78aa0c4d66
status: experimental
description: Detects Mimikatz MemSSP default log file creation
author: David ANDRE
references:
   - https://pentestlab.blog/2019/10/21/persistence-security-support-provider/
date: 2021/12/20
tags:
   - attack.credential_access
   - attack.t1003
logsource:
    product: windows
    category: file_event
detection: 
   mimikatz_memssp_filename:
      TargetFilename|endswith:
         - 'mimilsa.log'
   condition: mimikatz_memssp_filename
falsepositives:
   - Unlikely
level: critical

```
