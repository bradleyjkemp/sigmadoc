---
title: "RClone Execution"
aliases:
  - "/rule/a0d63692-a531-4912-ad39-4393325b2a9c"


tags:
  - attack.exfiltration
  - attack.t1567.002



status: deprecated





date: Sun, 24 Oct 2021 11:02:34 -0500


---

Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc

<!--more-->


## Known false-positives

* Legitimate RClone use



## References

* https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware
* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a
* https://labs.sentinelone.com/egregor-raas-continues-the-chaos-with-cobalt-strike-and-rclone
* https://www.splunk.com/en_us/blog/security/darkside-ransomware-splunk-threat-update-and-detections.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/deprecated/sysmon_rclone_execution.yml))
```yaml
title: RClone Execution
id: a0d63692-a531-4912-ad39-4393325b2a9c
status: deprecated
description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
tags:
    - attack.exfiltration
    - attack.t1567.002
author: Bhabesh Raj, Sittikorn S
date: 2021/05/10
modified: 2021/06/29
references:
    - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a
    - https://labs.sentinelone.com/egregor-raas-continues-the-chaos-with-cobalt-strike-and-rclone
    - https://www.splunk.com/en_us/blog/security/darkside-ransomware-splunk-threat-update-and-detections.html
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate RClone use
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: 'Rsync for cloud storage'
    selection2:
        CommandLine|contains|all:
            - '--config '
            - '--no-check-certificate '
            - ' copy '
    selection3:
        Image|endswith:
            - '\rclone.exe'
        CommandLine|contains:
            - 'mega'
            - 'pcloud'
            - 'ftp'
            - '--progress'
            - '--ignore-existing'
            - '--auto-confirm'
            - '--transfers'
            - '--multi-thread-streams'
    condition: 1 of selection*

```