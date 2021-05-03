---
title: "Possible DNS Rebinding"
aliases:
  - "/rule/eb07e747-2552-44cd-af36-b659ae0958e4"

tags:
  - attack.initial_access
  - attack.t1189



date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects several different DNS-answers by one domain with IPs from internal and external networks. Normally, DNS-answer contain TTL >100. (DNS-record will saved in host cache for a while TTL).

<!--more-->




## References

* https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325


## Raw rule
```yaml
title: Possible DNS Rebinding
id: eb07e747-2552-44cd-af36-b659ae0958e4
status: experimental
description: Detects several different DNS-answers by one domain with IPs from internal and external networks. Normally, DNS-answer contain TTL >100. (DNS-record will saved in host cache for a while TTL).
date: 2019/10/25
modified: 2020/08/28
author: Ilyas Ochkov, oscd.community
references:
    - https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325
tags:
    - attack.initial_access
    - attack.t1189
logsource:
    product: windows
    service: sysmon
detection:
    dns_answer:
        EventID: 22
        QueryName: '*'
        QueryStatus: '0'
    filter_int_ip:
        QueryResults|startswith:
            - '(::ffff:)?10.'
            - '(::ffff:)?192.168.'
            - '(::ffff:)?172.16.'
            - '(::ffff:)?172.17.'
            - '(::ffff:)?172.18.'
            - '(::ffff:)?172.19.'
            - '(::ffff:)?172.20.'
            - '(::ffff:)?172.21.'
            - '(::ffff:)?172.22.'
            - '(::ffff:)?172.23.'
            - '(::ffff:)?172.24.'
            - '(::ffff:)?172.25.'
            - '(::ffff:)?172.26.'
            - '(::ffff:)?172.27.'
            - '(::ffff:)?172.28.'
            - '(::ffff:)?172.29.'
            - '(::ffff:)?172.30.'
            - '(::ffff:)?172.31.'
            - '(::ffff:)?127.'
    timeframe: 30s
    condition: (dns_answer and filter_int_ip) and (dns_answer and not filter_int_ip) | count(QueryName) by ComputerName > 3
level: medium

```