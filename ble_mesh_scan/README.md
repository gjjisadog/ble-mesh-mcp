# 米家 USB 插座本地 BLE 控制

适用于已经注册、并使用 FE95 SpecV2 控制通道的 `de1.plug.wjzncz` 插座。设备地址和 DID 保存在当前 Windows 用户目录，不进入仓库。可以为多只同型号插座设置不同的本地名称；原有的 `lab_power` 配置和凭据路径继续有效。

本工具通过 Windows 自带蓝牙、Bleak 和 FE95 通道控制已经注册的插座。业务请求为 MIoT SpecV2 属性 `siid=2`、`piid=1`；每次调用重新完成 Admin Login，然后经 `001A` 发送，并从 `001B` 解密、校验响应。MCP 暴露 `list_devices`、`poweron(device)`、`poweroff(device)`、`powercycle(device)`、`poweron_many(devices)` 和 `poweroff_many(devices)`，没有原始写入接口。电源工具只接受本机登记过的设备名称。

## 一次性凭据准备

先创建 `%USERPROFILE%\.ble-mesh-mcp\lab_power.json`，填入你自己设备的 BLE 地址和米家 DID：

```json
{"address":"AA:BB:CC:DD:EE:FF","did":"1234567890"}
```

也可设置环境变量 `BLE_LAB_POWER_ADDRESS` 和 `BLE_LAB_POWER_DID`。然后在 PowerShell 中运行：

```powershell
cd .\ble_mesh_scan
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe bootstrap_credential.py
```

扫描程序打开的二维码并在手机确认。程序通过账号只读查询已绑定设备的 `gatt_ltmk`，用当前 Windows 用户的 DPAPI 加密后保存到 `%USERPROFILE%\.ble-mesh-mcp\lab_power.dpapi`。它不会打印密钥。换 Windows 用户或电脑后，需要重新执行凭据准备。

## 添加另一只同型号插座

先用米家将新插座绑定到你的账号，并使插座通电、靠近电脑。然后运行：

```powershell
cd .\ble_mesh_scan
.\.venv\Scripts\python.exe onboard_device.py add bench_power
```

脚本打开小米账号登录二维码，只筛选 `de1.plug.wjzncz`，并排除已在本机登记的 DID。若仍有多只候选插座，会显示名称和 DID，要求重新运行 `onboard_device.py add bench_power --did <DID>`；若云端不返回 BLE 地址，另加 `--address AA:BB:CC:DD:EE:FF`。它只读查询该设备的 `gatt_ltmk`，随后连接插座验证 Admin Login，不发送 ON/OFF。全部成功后才在 `%USERPROFILE%\.ble-mesh-mcp\devices.json` 保存名称、地址和 DID，并以 Windows DPAPI 将密钥加密保存到 `%USERPROFILE%\.ble-mesh-mcp\credentials\bench_power.dpapi`。同一地址或 DID 不能登记为两个名称。换 Windows 用户或电脑后需要重新准备凭据。

查看已接入的名称：

```powershell
.\.venv\Scripts\python.exe onboard_device.py list
```

原有 `lab_power.json` 与 `lab_power.dpapi` 无需迁移；首次添加新设备时，旧设备信息会一并写入 `devices.json`。MCP 的 `list_devices` 只返回名称、型号和凭据是否存在，不返回地址、DID 或密钥。

## 启动 MCP

```powershell
cd .\ble_mesh_scan
.\.venv\Scripts\python.exe mcp_server.py
```

服务器使用 MCP stdio 传输，启动后等待客户端输入，控制台不显示交互提示。通用 MCP 客户端配置示例：

```json
{
  "mcpServers": {
    "ble-lab-power": {
      "command": "C:\\path\\to\\ble-mesh-mcp\\ble_mesh_scan\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\ble-mesh-mcp\\ble_mesh_scan\\mcp_server.py"]
    }
  }
}
```

把实际绝对路径填入 MCP 客户端配置，重新连接后即可看到六个工具。例如 `poweroff(device="bench_power")` 控制第二只插座；`poweroff_many(devices=["lab_power", "bench_power"])` 一次请求关闭两只。批量返回每只设备的 `protocol_verified`，其中一只失败不会跳过其余设备。

同一个 MCP Server 进程会将 BLE 操作排队，批量控制是逐台执行，不保证继电器在同一瞬间切换。若多个独立进程共用蓝牙适配器，需要由上层避免同时访问。`powercycle` 仍针对单个名称执行；如需给多块 C2000 板卡断电，应在上层明确编排并逐台检查结果。

也可直接在 PowerShell 手动执行：

```powershell
.\.venv\Scripts\python.exe power_control.py poweron
.\.venv\Scripts\python.exe power_control.py poweroff
.\.venv\Scripts\python.exe power_control.py powercycle --off-seconds 5
.\.venv\Scripts\python.exe power_control.py powercycle --off-seconds 5 --mode manual
.\.venv\Scripts\python.exe power_control.py poweroff --device bench_power
```

工具返回 `transport_acked`、`property_status`、`protocol_verified`。`protocol_verified=true` 表示设备接收了 RXFER 包，并回复匹配 TID、SIID、PIID 且状态码为 0 的业务结果。`physical_state=null` 表示电脑没有独立的继电器状态传感器。

登录失败、连接断开、回复超时或状态码非零时，单次调用不会自动重发属性写入。电源工具要求 `device` 为本机已登记的名称；C2000 集成继续使用 `device="lab_power"`。

## 与 C2000 MCP 配合

上层 MCP 客户端在 Flash **全部目标镜像成功写入并确认**之后，先结束/释放 C2000 调试会话和板卡租约，再调用：

```json
{"tool":"powercycle","arguments":{"device":"lab_power","off_seconds":5,"mode":"auto_or_manual","reason":"after_flash"}}
```

`mode` 可选 `auto`、`manual`、`auto_or_manual`。默认的 `auto_or_manual` 会尝试自动断电；没有凭据、蓝牙不可用或自动过程失败时返回 `status="manual_required"`，上层必须暂停并等操作员断电至少 5 秒、重新上电且确认。`manual` 直接要求人工操作；`auto` 在失败时返回错误。只有 `status="completed"` 且 `protocol_verified=true`，才能把自动流程记为已执行。它表示 OFF 和 ON 都收到匹配的设备业务回复，不表示电脑有独立电压传感器。

`powercycle` 在同一 BLE 登录会话内发送 OFF、至少保持 5 秒、再发送 ON；OFF 尝试之后，即使等待被取消或 OFF 回复异常，也会尽力发送一次 ON 恢复。若 ON 失败或进程被终止，板卡**可能保持断电**，此时须人工检查供电。

C2000 的连接异常恢复也可在保存首次失败证据、确认没有 Flash 擦写正在执行、释放旧调试会话/租约后调用同一工具，并传 `reason="connection_recovery"`。断电重启会使此前的 C2000 会话和目标镜像身份失效；重新上电后须重新建立会话并验证固件身份，才能继续启动或 IPC 判断。烧录失败或结果未知时，不自动把电源循环当成烧录成功。

C2000 MCP 的可选断电集成可在配置后通过独立 stdio 客户端调用这里的 `powercycle`，固定使用 `lab_power`。其他 MCP 客户端也可按上述顺序编排。CLI 退出码 `0` 表示协议验证通过，`3` 表示需要人工断电重启，其他非零值表示失败；还应检查 JSON `protocol_verified`。

## 10 次翻转性能测试

仅在需要重复测试时手动运行：

```powershell
.\.venv\Scripts\python.exe toggle_benchmark.py
.\.venv\Scripts\python.exe toggle_benchmark.py --device bench_power
```

脚本先发送一次不计入统计的 OFF 来建立已知初始状态，然后在同一 BLE 会话中按 10 秒目标节拍交替发送 10 次 ON/OFF，最后请求 OFF。每次都要求 001A RXFER ACK 与 001B 解密后的匹配属性响应。失败立即停止，不重发控制命令。JSONL 日志只保存时间、状态码和性能元数据，不保存密钥。此项测量的是 **BLE 请求至协议回复** 的耗时，不是继电器机械动作的独立计时。
