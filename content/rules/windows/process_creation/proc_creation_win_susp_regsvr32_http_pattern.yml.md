---
title: "Suspicious Regsvr32 HTTP IP Pattern"
aliases:
  - "/rule/2dd2c217-bf68-437a-b57c-fe9fd01d5de8"


tags:
  - attack.defense_evasion
  - attack.t1218.010



status: experimental





date: Tue, 11 Jan 2022 10:46:48 +0100


---

Detects a certain command line flag combination used by regsvr32 when used to download and register a DLL from a remote address which uses HTTP (not HTTPS) and a IP address and not FQDN

<!--more-->


## Known false-positives

* FQDNs that start with a number



## References

* https://twitter.com/mrd0x/status/1461041276514623491c19-ps
* https://twitter.com/tccontre18/status/1480950986650832903


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_regsvr32_http_pattern.yml))
```yaml
title: Suspicious Regsvr32 HTTP IP Pattern
id: 2dd2c217-bf68-437a-b57c-fe9fd01d5de8
status: experimental
description: Detects a certain command line flag combination used by regsvr32 when used to download and register a DLL from a remote address which uses HTTP (not HTTPS) and a IP address and not FQDN
references:
    - https://twitter.com/mrd0x/status/1461041276514623491c19-ps
    - https://twitter.com/tccontre18/status/1480950986650832903
tags:
    - attack.defense_evasion
    - attack.t1218.010
author: Florian Roth
date: 2022/01/11
logsource:
    category: process_creation
    product: windows
detection:
    selection_flags:
        CommandLine|contains|all: 
            - ' /s'
            - ' /u'
    selection_ip:
        CommandLine|contains:
            - ' /i:http://1'
            - ' /i:http://2'
            - ' /i:http://3'
            - ' /i:http://4'
            - ' /i:http://5'
            - ' /i:http://6'
            - ' /i:http://7'
            - ' /i:http://8'
            - ' /i:http://9'
    condition: all of selection*
falsepositives:
    - FQDNs that start with a number
level: high
```
