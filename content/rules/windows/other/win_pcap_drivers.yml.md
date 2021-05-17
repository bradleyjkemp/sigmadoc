---
title: "Windows Pcap Drivers"
aliases:
  - "/rule/7b687634-ab20-11ea-bb37-0242ac130002"

tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040



status: experimental



level: medium



date: Wed, 10 Jun 2020 15:53:22 +0100


---

Detects Windows Pcap driver installation based on a list of associated .sys files.

<!--more-->


## Known false-positives

* unknown



## References

* https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more


## Raw rule
```yaml
title: Windows Pcap Drivers
id: 7b687634-ab20-11ea-bb37-0242ac130002
status: experimental
description: Detects Windows Pcap driver installation based on a list of associated .sys files.
author: Cian Heasley
date: 2020/06/10
references:
    - https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more
tags:
    - attack.discovery
    - attack.credential_access
    - attack.t1040
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 4697
        ServiceFileName:
          - '*pcap*'
          - '*npcap*'
          - '*npf*'
          - '*nm3*'
          - '*ndiscap*'
          - '*nmnt*'
          - '*windivert*'
          - '*USBPcap*'
          - '*pktmon*'
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

```
