### 3. crates/vpn-platform-windows/src/service_installer.rs
**Command injection prevention:**

- Added validation for `service_name`: must be alphanumeric/dash/underscore only, max 256 chars
- Added validation for `display_name`: max 256 chars  
- Added validation for `daemon_path`: must be absolute path, must exist, must be a file
- Added validation for `config_path`: must be absolute path if provided
- Quote escaping improvement: `\"` around daemon paths to handle spaces
- Note: `sc.exe` parses binPath internally, string building required. Full injection safety requires Windows API direct calls (future improvement)

---