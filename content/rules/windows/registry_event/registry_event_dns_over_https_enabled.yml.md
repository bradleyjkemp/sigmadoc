---
title: "DNS-over-HTTPS Enabled by Registry"
aliases:
  - "/rule/04b45a8a-d11d-49e4-9acc-4a1b524407a5"


tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.t1112



status: experimental





date: Tue, 31 Aug 2021 09:14:14 -0500


---

Detects when a user enables DNS-over-HTTPS. This can be used to hide internet activity or be used to hide the process of exfiltrating data. With this enabled organization will lose visibility into data such as query type, response and originating IP that are used to determine bad actors.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html
* https://github.com/elastic/detection-rules/issues/1371
* https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode
* https://admx.help/HKLM/Software/Policies/Mozilla/Firefox/DNSOverHTTPS


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_dns_over_https_enabled.yml))
```yaml
title: DNS-over-HTTPS Enabled by Registry
id: 04b45a8a-d11d-49e4-9acc-4a1b524407a5
status: experimental
description: Detects when a user enables DNS-over-HTTPS. This can be used to hide internet activity or be used to hide the process of exfiltrating data. With this enabled organization will lose visibility into data such as query type, response and originating IP that are used to determine bad actors.
author: Austin Songer
references:
    - https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html
    - https://github.com/elastic/detection-rules/issues/1371
    - https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode
    - https://admx.help/HKLM/Software/Policies/Mozilla/Firefox/DNSOverHTTPS
date: 2021/07/22
modified: 2022/01/13
logsource:
  product: windows
  category: registry_event
detection:
    selection_edge:
        EventType: SetValue
        TargetObject|endswith: '\SOFTWARE\Policies\Microsoft\Edge\BuiltInDnsClientEnabled'
        Details: 'DWORD (1)'
    selection_chrome:
        EventType: SetValue
        TargetObject|endswith: '\SOFTWARE\Google\Chrome\DnsOverHttpsMode'
        Details: 'DWORD (secure)'
    selection_firefox:
        EventType: SetValue
        TargetObject|endswith: '\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\Enabled'
        Details: 'DWORD (1)'
    condition: 1 of selection_*
falsepositives:
- Unlikely
level: medium
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1112
```
