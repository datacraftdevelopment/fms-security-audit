/bin/bash <<'FMS_AUDIT_EOF'
# FileMaker Security Audit: read-only OS check for macOS.
# Paste the whole script into Terminal inside your Screen Sharing session. It asks for
# an administrator password once (sudo), changes nothing, writes no files, and prints
# one result block that is also copied to the clipboard. Copy that block back.
set -u
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r\t'; }
s() { if [ -z "${1:-}" ]; then printf 'null'; else printf '"%s"' "$(esc "$1")"; fi; }
NC=""
nc() { NC="${NC:+$NC,}\"$1\":\"$(esc "$2")\""; }

echo "Administrator password (for read-only checks that need it; press Ctrl-C to skip them):"
trap ':' INT   # Ctrl-C at the sudo prompt cancels sudo, not the whole script
if sudo -v 2>/dev/null; then ELEV=true; SUDO="sudo -n"; else ELEV=false; SUDO=""; fi
trap - INT

OSJ="{\"name\":$(s "$(sw_vers -productName)"),\"version\":$(s "$(sw_vers -productVersion)"),\"build\":$(s "$(sw_vers -buildVersion)")}"

LIS=""
if [ "$ELEV" = true ]; then
  while read -r cmd pid name; do
    addr="${name%:*}"; port="${name##*:}"
    LIS="${LIS:+$LIS,}{\"port\":$port,\"address\":$(s "$addr"),\"pid\":$pid,\"process\":$(s "$cmd")}"
  done < <($SUDO lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $2, $9}' | sort -u -k3,3)
else
  while read -r local; do
    port="${local##*.}"; addr="${local%.*}"
    LIS="${LIS:+$LIS,}{\"port\":$port,\"address\":$(s "$addr"),\"pid\":null,\"process\":null}"
  done < <(netstat -anp tcp 2>/dev/null | awk '$6=="LISTEN" {print $4}' | sort -u)
  nc listener_processes "Needs administrator rights"
fi

AF=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
case "$AF" in *enabled*) AFE=true ;; *disabled*) AFE=false ;; *) AFE=null ;; esac
PF=null
if [ "$ELEV" = true ]; then
  case "$($SUDO pfctl -s info 2>/dev/null | grep -i '^Status')" in *Enabled*) PF=true ;; *Disabled*) PF=false ;; esac
else nc pf "Needs administrator rights"; fi
FW="{\"profiles\":[{\"name\":\"Application firewall\",\"enabled\":$AFE}],\"pf_enabled\":$PF,\"broad_allow_rules\":[]}"

# The history prints dates as 2026-10-20 or 10/20/2026 depending on the locale.
LAST=$(softwareupdate --history 2>/dev/null | grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{2}/[0-9]{2}/[0-9]{4}' | awk -F/ 'NF==3 {print $3"-"$1"-"$2; next} {print}' | sort | tail -1)
AUTO=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
case "$AUTO" in 1) AUTO=true ;; 0) AUTO=false ;; *) AUTO=null ;; esac
PAT="{\"last_installed\":$(s "$LAST"),\"auto_updates\":$AUTO}"

ADM=""
for u in $(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2); do ADM="${ADM:+$ADM,}$(s "$u")"; done

case "$(fdesetup status 2>/dev/null)" in *"is On"*) FV=true ;; *"is Off"*) FV=false ;; *) FV=null ;; esac
DISK="[{\"volume\":\"/\",\"encrypted\":$FV}]"

AV="{\"name\":\"XProtect (built in)\",\"running\":true,\"signature_age_days\":null}"
# Match vendor names as whole words in executable paths, not as substrings ("ESET" is inside "CascadeSets").
PROCS=$(ps -axo comm= 2>/dev/null)
for p in Sophos CrowdStrike falcond SentinelOne sentineld Malwarebytes ESET Bitdefender "Trend ?Micro" McAfee Symantec Webroot Huntress; do
  if printf '%s\n' "$PROCS" | grep -Eiq "(^|[^[:alnum:]])${p}s?([^[:alnum:]]|$)"; then
    label=$(printf '%s' "$p" | tr -d '?')
    AV="$AV,{\"name\":$(s "$label"),\"running\":true,\"signature_age_days\":null}"
  fi
done
nc av_exclusions "Not available on macOS; review manually"

DATA=""
[ -d "/Library/FileMaker Server/Data/Databases" ] && DATA="\"/Library/FileMaker Server/Data/Databases\""

JSON="{\"platform\":\"mac\",\"schema\":1,\"collected_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"hostname\":$(s "$(hostname)"),\"elevated\":$ELEV,\"os\":$OSJ,\"listeners\":[$LIS],\"firewall\":$FW,\"patching\":$PAT,\"local_admins\":[$ADM],\"disk_encryption\":$DISK,\"antivirus\":{\"products\":[$AV]},\"av_exclusions\":null,\"fms_data_paths\":[$DATA],\"not_checked\":{$NC}}"

B64=$(printf '%s' "$JSON" | gzip -c | base64 | fold -w 76)
SHA=$(printf '%s' "$JSON" | shasum -a 256 | cut -d' ' -f1)
BLOCK=$(printf -- '----- FMS-AUDIT OS BEGIN v1 -----\n%s\nsha256: %s\n----- FMS-AUDIT OS END -----' "$B64" "$SHA")
echo
echo "$BLOCK"
if printf '%s' "$BLOCK" | pbcopy 2>/dev/null; then echo; echo "Copied to the clipboard. Paste it back on your laptop with: python -m audit os-import"; fi
[ "$ELEV" = true ] || echo "Not running with administrator rights: some checks will show as Not checked."
sudo -k 2>/dev/null
FMS_AUDIT_EOF
