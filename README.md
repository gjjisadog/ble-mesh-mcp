# Xiaomi BLE Mesh lab power MCP

A Windows Python/Bleak tool for multiple registered Xiaomi BLE Mesh USB plugs of
the supported model. It exposes
`list_devices`, named `poweron`/`poweroff`/`powercycle`, and batch
`poweron_many`/`poweroff_many` as MCP tools. The power-cycle operation
holds OFF for at least five seconds by default, then restores ON and checks the
device's MIoT response. One Bluetooth adapter processes requests sequentially;
batch results report each plug separately. The PC does not independently measure outlet voltage.

The repository includes a BLE advertisement scanner and a local MIoT control
implementation. Registration research notes, device captures, cloud responses,
credentials, and machine-specific device identifiers are excluded from this
public repository.

See [setup and MCP configuration](ble_mesh_scan/README.md).
