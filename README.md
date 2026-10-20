# CVE Submission: TP-Link Archer AX1500 OpenVPN LuCI Handler DoS

## Summary

An authenticated attacker can crash the OpenVPN LuCI Lua handler on TP-Link
Archer AX1500 by sending a crafted POST/GET to `openvpn?form=config` with
`enabled=on&proto=udp` (without a port parameter). This causes a Lua runtime
error ("attempt to compare nil with number") in the handler, permanently
corrupting the router's OpenVPN UCI configuration section.

## Affected Products

- TP-Link Archer AX1500 v1.20
- Firmware: 1.3.12 Build 20250828 Rel. 26873(4555)

## Vulnerability Details

**CWE**: CWE-476 (NULL Pointer Dereference / Lua nil comparison)
          CWE-400 (Uncontrolled Resource Consumption)

**CVSS v3.1**: 6.5 (MEDIUM)
- Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
- Authenticated (low privilege), network accessible

### Technical Details

The `/cgi-bin/luci/;stok=<SESSION>/admin/openvpn?form=config` handler reads
the UCI value for `vpn_port` and passes it to `tonumber()` for comparison.
When the `port` UCI field is absent (nil) and `proto=udp` is submitted without
a port value, the handler executes:

```lua
assert(port_val > 0)   -- port_val is nil → "attempt to compare nil with number"
```

**Crash trigger** (authenticated session required):
```
GET /cgi-bin/luci/;stok=<SESSION>/admin/openvpn?form=config
    &operation=write&enabled=on&proto=udp
```

Response:
```json
{"errorcode":"attempt to compare nil with number","success":false}
```

The partial write before the crash leaves the UCI `vpn` section in a corrupted
state. All subsequent reads from `openvpn?form=config` then return:
```json
{"errorcode":"invalid uci config","success":false}
```

This corruption persists across reboots (UCI data is stored in flash).

### Impact

- **DoS**: OpenVPN configuration becomes permanently inaccessible/broken
- **Persistence**: UCI corruption survives reboots; requires factory reset to fix
- **Chained**: Forces admin to factory reset, creating a window for other attacks

### Proof-of-Concept

See: `poc_openvpn_dos.py`

## Timeline

- **2026-10-21**: Discovered during authorized security testing
- **Submitted to**: MITRE CVE Program, TP-Link PSIRT
