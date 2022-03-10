---
title: "Sysmon Configuration Change"
aliases:
  - "/rule/8ac03a65-6c84-4116-acad-dc1558ff7a77"


tags:
  - attack.defense_evasion



status: experimental





date: Wed, 12 Jan 2022 20:27:56 +0100


---

Detects a Sysmon configuration change, which could be the result of a legitimate reconfiguration or someone trying manipulate the configuration

<!--more-->


## Known false-positives

* legitimate administrative action



## References

* https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/sysmon/sysmon_config_modification.yml))
```yaml
title: Sysmon Configuration Change
id: 8ac03a65-6c84-4116-acad-dc1558ff7a77
description: Detects a Sysmon configuration change, which could be the result of a legitimate reconfiguration or someone trying manipulate the configuration
status: experimental
author: frack113
date: 2022/01/12
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 16
    # To avoid FP just add
    # filter:
    #      ConfigurationFileHash: 'SHA256=The_Hash_Of_Your_Valid_Config_XML'
    # condition: selection and not filter
    condition: selection
falsepositives:
    - legitimate administrative action
level: medium 
tags:
    - attack.defense_evasion

```
