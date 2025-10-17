# TinySOCS Sysmon Integration
#
# - Put binaries in: ../sysmon-bin/ (ignored by git)
#   * Sysmon64.exe  (required)
#   * Optional: Sysmon.exe for 32-bit systems
#
# - Keep configs/scripts here:
#   * sysmon-config.xml
#   * install_sysmon.ps1 / uninstall_sysmon.ps1
#
# Install/update:
#   powershell -ExecutionPolicy Bypass -File .\install_sysmon.ps1
#
# Uninstall:
#   powershell -ExecutionPolicy Bypass -File .\uninstall_sysmon.ps1