---
title: "Quick Execution of a Series of Suspicious Commands"
aliases:
  - "/rule/61ab5496-748e-4818-a92f-de78e20fe7f1"


tags:
  - car.2013-04-002
  - attack.execution
  - attack.t1059



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects multiple suspicious process in a limited timeframe

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://car.mitre.org/wiki/CAR-2013-04-002


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_multiple_suspicious_cli.yml))
```yaml
title: Quick Execution of a Series of Suspicious Commands
id: 61ab5496-748e-4818-a92f-de78e20fe7f1
description: Detects multiple suspicious process in a limited timeframe
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-04-002
author: juju4
date: 2019/01/16
modified: 2021/06/13
tags:
    - car.2013-04-002
    - attack.execution
    - attack.t1059 
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - arp.exe
            - at.exe
            - attrib.exe
            - cscript.exe
            - dsquery.exe
            - hostname.exe
            - ipconfig.exe
            - mimikatz.exe
            - nbtstat.exe
            - net.exe
            - netsh.exe
            - nslookup.exe
            - ping.exe
            - quser.exe
            - qwinsta.exe
            - reg.exe
            - runas.exe
            - sc.exe
            - schtasks.exe
            - ssh.exe
            - systeminfo.exe
            - taskkill.exe
            - telnet.exe
            - tracert.exe
            - wscript.exe
            - xcopy.exe
            - pscp.exe
            - copy.exe
            - robocopy.exe
            - certutil.exe
            - vssadmin.exe
            - powershell.exe
            - wevtutil.exe
            - psexec.exe
            - bcedit.exe
            - wbadmin.exe
            - icacls.exe
            - diskpart.exe
    timeframe: 5m
    condition: selection | count() by MachineName > 5
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low

```
