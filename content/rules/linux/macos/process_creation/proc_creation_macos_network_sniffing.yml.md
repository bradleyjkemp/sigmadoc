---
title: "Network Sniffing"
aliases:
  - "/rule/adc9bcc4-c39c-4f6b-a711-1884017bf043"


tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the usage of tooling to sniff network traffic. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_network_sniffing.yml))
```yaml
title: Network Sniffing
id: adc9bcc4-c39c-4f6b-a711-1884017bf043
status: test
description: Detects the usage of tooling to sniff network traffic. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md
date: 2020/10/14
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    Image|endswith:
      - '/tcpdump'
      - '/tshark'
  condition: selection
falsepositives:
  - Legitimate administration activities
level: informational
tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040

```
