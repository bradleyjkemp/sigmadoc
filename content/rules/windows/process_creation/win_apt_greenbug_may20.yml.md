---
title: "Greenbug Campaign Indicators"
aliases:
  - "/rule/3711eee4-a808-4849-8a14-faf733da3612"

tags:
  - attack.g0049
  - attack.execution
  - attack.t1059.001
  - attack.t1086
  - attack.command_and_control
  - attack.t1105
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.005



date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects tools and process executions as observed in a Greenbug campaign in May 2020

<!--more-->


## Known false-positives

* Unknown



## References

* https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/greenbug-espionage-telco-south-asia


## Raw rule
```yaml
title: Greenbug Campaign Indicators
id: 3711eee4-a808-4849-8a14-faf733da3612
status: experimental
description: Detects tools and process executions as observed in a Greenbug campaign in May 2020
references:
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/greenbug-espionage-telco-south-asia
author: Florian Roth
date: 2020/05/20
modified: 2020/08/27
tags:
    - attack.g0049
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
    - attack.command_and_control
    - attack.t1105
    - attack.defense_evasion
    - attack.t1036  # an old one
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all: 
            - 'bitsadmin /transfer'
            - 'CSIDL_APPDATA'
    selection2:
        CommandLine|contains: 
            - 'CSIDL_SYSTEM_DRIVE'
    selection3: 
        CommandLine|contains:
            - '\msf.ps1'
            - '8989 -e cmd.exe'
            - 'system.Data.SqlClient.SqlDataAdapter($cmd); [void]$da.fill'
            - '-nop -w hidden -c $k=new-object'
            - '[Net.CredentialCache]::DefaultCredentials;IEX '
            - ' -nop -w hidden -c $m=new-object net.webclient;$m'
            - '-noninteractive -executionpolicy bypass whoami'
            - '-noninteractive -executionpolicy bypass netstat -a'
            - 'L3NlcnZlc'  # base64 encoded '/server='
    selection4:
        Image|endswith:
            - '\adobe\Adobe.exe'
            - '\oracle\local.exe'
            - '\revshell.exe'
            - 'infopagesbackup\ncat.exe'
            - 'CSIDL_SYSTEM\cmd.exe'
            - '\programdata\oracle\java.exe'
            - 'CSIDL_COMMON_APPDATA\comms\comms.exe'
            - '\Programdata\VMware\Vmware.exe'
    condition: 1 of them
falsepositives:
    - Unknown
level: critical

```