---
title: "Windows Pcap Drivers"
aliases:
  - "/rule/7b687634-ab20-11ea-bb37-0242ac130002"
ruleid: 7b687634-ab20-11ea-bb37-0242ac130002

tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040



status: test





date: Wed, 10 Jun 2020 15:53:22 +0100


---

Detects Windows Pcap driver installation based on a list of associated .sys files.

<!--more-->


## Known false-positives

* unknown



## References

* https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_pcap_drivers.yml))
```yaml
title: Windows Pcap Drivers
id: 7b687634-ab20-11ea-bb37-0242ac130002
status: test
description: Detects Windows Pcap driver installation based on a list of associated .sys files.
author: Cian Heasley
references:
  - https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more
date: 2020/06/10
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4697
    ServiceFileName|contains:
      - 'pcap'
      - 'npcap'
      - 'npf'
      - 'nm3'
      - 'ndiscap'
      - 'nmnt'
      - 'windivert'
      - 'USBPcap'
      - 'pktmon'
  condition: selection
fields:
  - EventID
  - ServiceFileName
  - Account_Name
  - Computer_Name
  - Originating_Computer
  - ServiceName
falsepositives:
  - unknown
level: medium
tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040

```
