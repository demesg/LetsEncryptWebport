# WebPort ACME Automation (CSR Mode)

This PowerShell script automates SSL/TLS certificate issuance, installation, renewal, and cleanup for **WebPort** using **ACME (Let’s Encrypt)**.  
It reads CSR and certificate metadata directly from the WebPort SQLite database and updates all certificate values back into WebPort.

> ✅ Supports any ACME DNS plugin, configurable by `-DnsPlugin` and `-PluginArgsFile`.

---

## ✅ Features

✔ Reads **CSR** (and CN/SAN) from WebPort database  
✔ Issues an ACME certificate via **Posh-ACME**  
✔ Supports multiple DNS plugins  
✔ Loads DNS plugin parameters from external file  
✔ Generates and installs `.p12` into WebPort  
✔ Updates WebPort DB: leaf, intermediate, root  
✔ Removes old certificates from the Windows certificate store  
✔ Automatically sets Windows firewall rule for WebPort port  
✔ Restarts WebPort (service or EXE) automatically  
✔ Failsafe mode to wipe all WebPort SSL config  
✔ Validates admin + PowerShell 7+  
✔ Ensures Posh-ACME module is installed  

---

## 🧩 Requirements

| Component | Required |
|----------|----------|
| Windows | ✅ |
| PowerShell 7+ | ✅ |
| Administrator privileges | ✅ |
| Posh-ACME module | Auto-installed |
| OpenSSL | Required for `.p12` build |
| WebPort installation | ✅ |

---

## 🔧 Parameters

| Parameter | Description |
|-----------|-------------|
| `-PfxPass` | Password for `.p12` bundle (mandatory unless `-failsafe`) |
| `-IssueCert` | Requests a certificate using CSR + ACME |
| `-ExportPfx` | Builds `webport.p12` for WebPort |
| `-DnsPlugin` | Which Posh-ACME DNS plugin to use |
| `-PluginArgsFile` | Path to file containing DNS plugin arguments |
| `-ZoneName` | DNS zone name |
| `-ResourceGroup` | Azure example; not required if not Azure |
| `-WebPortDataPath` | WebPort data root |
| `-WebPortProgPath` | WebPort program folder |
| `-failsafe` | Clears SSL from DB, keystore & restarts WebPort |

---

## 🔐 Plugin Arguments

### Providing plugin configuration  
You can pass DNS plugin configuration using:  

