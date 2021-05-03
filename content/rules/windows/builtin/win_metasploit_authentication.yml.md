---
title: "Metasploit SMB Authentication"
aliases:
  - "/rule/72124974-a68b-4366-b990-d30e0b2a190d"

tags:
  - attack.lateral_movement
  - attack.t1077
  - attack.t1021.002



date: Wed, 6 May 2020 16:42:27 +0200


---

Alerts on Metasploit host's authentications on the domain.

<!--more-->


## Known false-positives

* Linux hostnames composed of 16 characters.



## References

* https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb


## Raw rule
```yaml
title: Metasploit SMB Authentication
description: Alerts on Metasploit host's authentications on the domain.
id: 72124974-a68b-4366-b990-d30e0b2a190d
author: Chakib Gzenayi (@Chak092), Hosni Mribah
date: 2020/05/06
modified: 2020/08/23
references: 
    - https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb
tags:
    - attack.lateral_movement
    - attack.t1077          # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
        - 4625
        - 4624
        LogonType: 3
        AuthenticationPackage: 'NTLM'
        WorkstationName|re: '^[A-Za-z0-9]{16}$'
    selection2:
        ProcessName:
        EventID: 4776
        SourceWorkstation|re: '^[A-Za-z0-9]{16}$'
    condition: selection1 OR selection2
falsepositives:
    - Linux hostnames composed of 16 characters.
level: high

```