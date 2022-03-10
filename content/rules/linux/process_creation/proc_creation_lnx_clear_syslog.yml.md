---
title: "Commands to Clear or Remove the Syslog"
aliases:
  - "/rule/3fcc9b35-39e4-44c0-a2ad-9e82b6902b31"


tags:
  - attack.impact
  - attack.t1565.001



status: experimental





date: Fri, 15 Oct 2021 15:43:42 -0400


---

Detects specific commands commonly used to remove or empty the syslog.

<!--more-->


## Known false-positives

* Log rotation.



## References

* https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_clear_syslog.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_clear_syslog.yml))
```yaml
title: Commands to Clear or Remove the Syslog
id: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
status: experimental
description: Detects specific commands commonly used to remove or empty the syslog.
date: 2021/10/15
author: Max Altgelt, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
tags:
   - attack.impact
   - attack.t1565.001
references:
   - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_clear_syslog.yml
logsource:
   product: linux
   category: process_creation
detection:
   selection:
      CommandLine|contains:
         - 'rm /var/log/syslog'
         - 'rm -r /var/log/syslog'
         - 'rm -f /var/log/syslog'
         - 'rm -rf /var/log/syslog'
         - 'mv /var/log/syslog'
         - ' >/var/log/syslog'
         - ' > /var/log/syslog'
   condition: selection
falsepositives:
   - Log rotation.
level: high
```
