---
title: "Possible PrintNightmare Print Driver Install"
aliases:
  - "/rule/7b33baef-2a75-4ca3-9da4-34f9a15382d8"
ruleid: 7b33baef-2a75-4ca3-9da4-34f9a15382d8

tags:
  - attack.execution
  - cve.2021.1678
  - cve.2021.1675
  - cve.2021.34527



status: stable





date: Tue, 24 Aug 2021 00:58:36 -0400


---

Detects the remote installation of a print driver which is possible indication of the exploitation of PrintNightmare (CVE-2021-1675).
The occurrence of print drivers being installed remotely via RPC functions should be rare, as print drivers are normally installed locally and or through group policy.


<!--more-->


## Known false-positives

* Legitimate remote alteration of a printer driver.



## References

* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/93d1915d-4d9f-4ceb-90a7-e8f2a59adc29
* https://github.com/zeek/zeek/blob/master/scripts/base/protocols/dce-rpc/consts.zeek
* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
* https://github.com/corelight/CVE-2021-1675
* https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_dce_rpc_mitre_bzar_persistence.yml
* https://old.zeek.org/zeekweek2019/slides/bzar.pdf
* https://www.crowdstrike.com/blog/cve-2021-1678-printer-spooler-relay-security-advisory/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/zeek/zeek_dce_rpc_printnightmare_print_driver_install.yml))
```yaml
title: Possible PrintNightmare Print Driver Install
id: 7b33baef-2a75-4ca3-9da4-34f9a15382d8
description: |
    Detects the remote installation of a print driver which is possible indication of the exploitation of PrintNightmare (CVE-2021-1675).
    The occurrence of print drivers being installed remotely via RPC functions should be rare, as print drivers are normally installed locally and or through group policy.
author: '@neu5ron (Nate Guagenti)'
date: 2021/08/23
references:
    - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/93d1915d-4d9f-4ceb-90a7-e8f2a59adc29
    - https://github.com/zeek/zeek/blob/master/scripts/base/protocols/dce-rpc/consts.zeek
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
    - https://github.com/corelight/CVE-2021-1675
    - https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_dce_rpc_mitre_bzar_persistence.yml
    - https://old.zeek.org/zeekweek2019/slides/bzar.pdf
    - https://www.crowdstrike.com/blog/cve-2021-1678-printer-spooler-relay-security-advisory/

tags:
    - attack.execution
    - cve.2021.1678
    - cve.2021.1675
    - cve.2021.34527
logsource:
    product: zeek
    service: dce_rpc
detection:
    printer_operation:
        operation:
            - 'RpcAsyncInstallPrinterDriverFromPackage' # "76f03f96-cdfd-44fc-a22c-64950a001209",0x3e
            - 'RpcAsyncAddPrintProcessor' # "76f03f96-cdfd-44fc-a22c-64950a001209",0x2c
            - 'RpcAddPrintProcessor' # "12345678-1234-abcd-ef00-0123456789ab",0x0e
            - 'RpcAddPrinterDriverEx' # "12345678-1234-abcd-ef00-0123456789ab",0x59
            - 'RpcAddPrinterDriver' # "12345678-1234-abcd-ef00-0123456789ab",0x09
            - 'RpcAsyncAddPrinterDriver' # "76f03f96-cdfd-44fc-a22c-64950a001209",0x27
    condition: printer_operation
falsepositives:
    - Legitimate remote alteration of a printer driver.
level: medium
fields:
    - id.orig_h
    - id.resp_h
    - id.resp_p
    - operation
    - endpoint
    - named_pipe
    - uid
status: stable

```