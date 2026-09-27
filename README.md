# Xiaomi BLE Mesh lab power MCP

A Windows Python/Bleak tool for a registered Xiaomi BLE Mesh USB plug. It exposes
`poweron`, `poweroff`, and `powercycle` as MCP tools. The power-cycle operation
holds OFF for at least five seconds by default, then restores ON and checks the
device's MIoT response. The PC does not independently measure outlet voltage.

The repository includes a BLE advertisement scanner and a local MIoT control
implementation. Registration research notes, device captures, cloud responses,
credentials, and machine-specific device identifiers are excluded from this
public repository.

See [setup and MCP configuration](ble_mesh_scan/README.md).
