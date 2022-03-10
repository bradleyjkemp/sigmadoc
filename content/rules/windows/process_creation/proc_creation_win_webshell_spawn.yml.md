---
title: "Shells Spawned by Web Servers"
aliases:
  - "/rule/8202070f-edeb-4d31-a010-a26c72ac5600"


tags:
  - attack.persistence
  - attack.t1505.003
  - attack.t1190



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack

<!--more-->


## Known false-positives

* Particular web applications may spawn a shell process legitimately




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_webshell_spawn.yml))
```yaml
title: Shells Spawned by Web Servers
id: 8202070f-edeb-4d31-a010-a26c72ac5600
status: test
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
date: 2019/01/16
modified: 2022/01/06
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\php-cgi.exe'
      - '\tomcat.exe'
      - '\UMWorkerProcess.exe'  # https://www.fireeye.com/blog/threat-research/2021/03/detection-response-to-exploitation-of-microsoft-exchange-zero-day-vulnerabilities.html
      - '\ws_TomcatService.exe'  # https://digital.nhs.uk/cyber-alerts/2022/cc-4002
    Image|endswith:
      - '\cmd.exe'
      - '\sh.exe'
      - '\bash.exe'
      - '\powershell.exe'
      - '\bitsadmin.exe'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Particular web applications may spawn a shell process legitimately
level: high
tags:
  - attack.persistence
  - attack.t1505.003
  - attack.t1190

```