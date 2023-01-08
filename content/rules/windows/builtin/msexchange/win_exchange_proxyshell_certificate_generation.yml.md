---
title: "Certificate Request Export to Exchange Webserver"
aliases:
  - "/rule/b7bc7038-638b-4ffd-880c-292c692209ef"
ruleid: b7bc7038-638b-4ffd-880c-292c692209ef

tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Mon, 23 Aug 2021 11:17:10 +0200


---

Detects a write of an Exchange CSR to an untypical directory or with aspx name suffix which can be used to place a webshell

<!--more-->


## Known false-positives

* unlikely



## References

* https://twitter.com/GossiTheDog/status/1429175908905127938


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/msexchange/win_exchange_proxyshell_certificate_generation.yml))
```yaml
title: Certificate Request Export to Exchange Webserver
id: b7bc7038-638b-4ffd-880c-292c692209ef
status: experimental
description: Detects a write of an Exchange CSR to an untypical directory or with aspx name suffix which can be used to place a webshell
references:
    - https://twitter.com/GossiTheDog/status/1429175908905127938
author: Max Altgelt
date: 2021/08/23
logsource:
    service: msexchange-management
    product: windows
detection:
    export_command:
        - 'New-ExchangeCertificate'
        - ' -GenerateRequest'
        - ' -BinaryEncoded'
        - ' -RequestFile'
    export_params:
        - '\\\\localhost\\C$'
        - '\\\\127.0.0.1\\C$'
        - 'C:\\inetpub'
        - '.aspx'
    condition: all of export_command and export_params
falsepositives:
    - unlikely
level: critical
tags:
    - attack.persistence
    - attack.t1505.003

```
