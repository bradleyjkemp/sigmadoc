---
title: "WMI Reconnaissance List Remote Services"
aliases:
  - "/rule/09af397b-c5eb-4811-b2bb-08b3de464ebf"


tags:
  - attack.execution
  - attack.t1047



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

An adversary might use WMI to check if a certain Remote Service is running on a remote device.
When the test completes, a service information will be displayed on the screen if it exists.
A common feedback message is that "No instance(s) Available" if the service queried is not running.
A common error message is "Node - (provided IP or default) ERROR Description =The RPC server is unavailable" if the provided remote host is unreacheable


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wmic


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_wmic_remote_service.yml))
```yaml
title: WMI Reconnaissance List Remote Services
id: 09af397b-c5eb-4811-b2bb-08b3de464ebf
status: experimental
description: |
  An adversary might use WMI to check if a certain Remote Service is running on a remote device.
  When the test completes, a service information will be displayed on the screen if it exists.
  A common feedback message is that "No instance(s) Available" if the service queried is not running.
  A common error message is "Node - (provided IP or default) ERROR Description =The RPC server is unavailable" if the provided remote host is unreacheable
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wmic
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \WMIC.exe
        CommandLine|contains|all:
            - '/node:'
            - service 
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.execution
    - attack.t1047

```
