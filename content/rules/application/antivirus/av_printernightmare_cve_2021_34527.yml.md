---
title: "Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection"
aliases:
  - "/rule/6fe1719e-ecdf-4caf-bffe-4f501cb0a561"
ruleid: 6fe1719e-ecdf-4caf-bffe-4f501cb0a561

tags:
  - attack.privilege_escalation
  - attack.t1055



status: stable





date: Thu, 1 Jul 2021 13:04:19 +0700


---

Detects the suspicious file that is created from PoC code against Windows Print Spooler Remote Code Execution Vulnerability CVE-2021-34527 (PrinterNightmare), CVE-2021-1675 .

<!--more-->


## Known false-positives

* Unlikely



## References

* https://twitter.com/mvelazco/status/1410291741241102338
* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/application/antivirus/av_printernightmare_cve_2021_34527.yml))
```yaml
title: Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection
id: 6fe1719e-ecdf-4caf-bffe-4f501cb0a561
status: stable
description: Detects the suspicious file that is created from PoC code against Windows Print Spooler Remote Code Execution Vulnerability CVE-2021-34527 (PrinterNightmare), CVE-2021-1675 .
references:
    - https://twitter.com/mvelazco/status/1410291741241102338
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
author: Sittikorn S, Nuttakorn T
date: 2021/07/01
modified: 2021/11/23
tags:
    - attack.privilege_escalation
    - attack.t1055
logsource:
    product: antivirus
detection:
    selection:
        Filename|contains: 'C:\Windows\System32\spool\drivers\x64\'
    condition: selection
fields:
    - Signature
    - Filename
    - ComputerName
falsepositives:
    - Unlikely
level: critical

```
