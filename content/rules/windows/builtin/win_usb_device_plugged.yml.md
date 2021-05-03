---
title: "USB Device Plugged"
aliases:
  - "/rule/1a4bd6e3-4c6e-405d-a9a3-53a116e341d4"

tags:
  - attack.initial_access
  - attack.t1200



date: Thu, 9 Nov 2017 08:40:46 +0100


---

Detects plugged USB devices

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/
* https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/


## Raw rule
```yaml
title: USB Device Plugged
id: 1a4bd6e3-4c6e-405d-a9a3-53a116e341d4
description: Detects plugged USB devices
references:
    - https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/
    - https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/
status: experimental
author: Florian Roth
date: 2017/11/09
tags:
    - attack.initial_access
    - attack.t1200
logsource:
    product: windows
    service: driver-framework
detection:
    selection:
        EventID:
            - 2003  # Loading drivers
            - 2100  # Pnp or power management
            - 2102  # Pnp or power management
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: low

```