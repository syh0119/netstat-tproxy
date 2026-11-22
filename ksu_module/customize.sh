#!/system/bin/sh
SKIPUNZIP=0
ui_print "- Installing FlClash TProxy Backend..."
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
ui_print "- Installed. Install NetStat APK and reboot (or start service.sh)."
