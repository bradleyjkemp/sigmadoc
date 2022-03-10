---
title: "ADFS Database Named Pipe Connection"
aliases:
  - "/rule/1ea13e8c-03ea-409b-877d-ce5c3d2c1cb3"


tags:
  - attack.collection
  - attack.t1005



status: experimental





date: Fri, 8 Oct 2021 01:57:22 -0400


---

Detects suspicious local connections via a named pipe to the AD FS configuration database (Windows Internal Database). Used to access information such as the AD FS configuration settings which contains sensitive information used to sign SAML tokens.

<!--more-->


## Known false-positives

* Processes in the filter condition



## References

* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/ADFSDBNamedPipeConnection.yaml
* https://o365blog.com/post/adfs/
* https://github.com/Azure/SimuLand


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/pipe_created/pipe_created_susp_adfs_namedpipe_connection.yml))
```yaml
title: ADFS Database Named Pipe Connection
id: 1ea13e8c-03ea-409b-877d-ce5c3d2c1cb3
description: Detects suspicious local connections via a named pipe to the AD FS configuration database (Windows Internal Database). Used to access information such as the AD FS configuration settings which contains sensitive information used to sign SAML tokens.
status: experimental
date: 2021/10/08
modified: 2022/02/16
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/ADFSDBNamedPipeConnection.yaml
    - https://o365blog.com/post/adfs/
    - https://github.com/Azure/SimuLand
tags:
    - attack.collection
    - attack.t1005
logsource:
    product: windows
    category: pipe_created
detection:
    selection:
        PipeName: '\MICROSOFT##WID\tsql\query'
    filter:
        Image|endswith:
            - '\Microsoft.IdentityServer.ServiceHost.exe'
            - '\Microsoft.Identity.Health.Adfs.PshSurrogate.exe'
            - '\AzureADConnect.exe'
            - '\Microsoft.Tri.Sensor.exe'
            - '\wsmprovhost.exe'
            - '\mmc.exe'
            - '\sqlservr.exe'
            - '\tssdis.exe'
    condition: selection and not filter
falsepositives:
    - Processes in the filter condition
level: high

```
