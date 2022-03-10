---
title: "Python Initiated Connection"
aliases:
  - "/rule/bef0bc5a-b9ae-425d-85c6-7b2d705980c6"


tags:
  - attack.discovery
  - attack.t1046



status: experimental





date: Fri, 10 Dec 2021 16:31:16 +0100


---

Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation

<!--more-->


## Known false-positives

* Legitimate python script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md#atomic-test-4---port-scan-using-python
* https://pypi.org/project/scapy/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_python.yml))
```yaml
title: Python Initiated Connection
id: bef0bc5a-b9ae-425d-85c6-7b2d705980c6
status: experimental
description: Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md#atomic-test-4---port-scan-using-python
  - https://pypi.org/project/scapy/
date: 2021/12/10
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|contains: python
  condition: selection
falsepositives:
  - Legitimate python script
level: high
tags:
    - attack.discovery
    - attack.t1046
```
