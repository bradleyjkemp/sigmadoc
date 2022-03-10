---
title: "Scheduled Cron Task/Job"
aliases:
  - "/rule/6b14bac8-3e3a-4324-8109-42f0546a347f"


tags:
  - attack.execution
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.003



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_schedule_task_job_cron.yml))
```yaml
title: Scheduled Cron Task/Job
id: 6b14bac8-3e3a-4324-8109-42f0546a347f
status: test
description: Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.md
date: 2020/10/06
modified: 2021/11/27
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - 'crontab'
    CommandLine|contains:
      - '/tmp/'
  condition: selection
falsepositives:
  - Legitimate administration activities
level: medium
tags:
  - attack.execution
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.003

```
