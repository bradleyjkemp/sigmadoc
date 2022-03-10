---
title: "Capture a Network Trace with netsh.exe"
aliases:
  - "/rule/d3c3861d-c504-4c77-ba55-224ba82d0118"


tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040



status: test





date: Fri, 25 Oct 2019 18:01:36 +0300


---

Detects capture a network trace via netsh.exe trace functionality

<!--more-->


## Known false-positives

* Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason



## References

* https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_netsh_packet_capture.yml))
```yaml
title: Capture a Network Trace with netsh.exe
id: d3c3861d-c504-4c77-ba55-224ba82d0118
status: test
description: Detects capture a network trace via netsh.exe trace functionality
author: Kutepov Anton, oscd.community
references:
  - https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - netsh
      - trace
      - start
  condition: selection
falsepositives:
  - Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason
level: medium
tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040

```
