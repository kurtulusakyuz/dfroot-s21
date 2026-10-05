#!/system/bin/sh
# ksudshim: manager'in libksud.so yerine cagirdigi uyumluluk katmani.
# Cagrilma: sh ksudshim.sh <ksud argumanlari>  (getKsuDaemonPath remap)
# Neden: root sh'den /data binary exec = DEFEX oldurur; sh script okumak
# guvenli. Tum agir is mrun.sh'de; burada CLI yuzeyi + JSON uretimi.
# NOT: "debug su" (libsu root-shell kurulumu) -> gercek sh'e exec olur,
# boylece libsu saglikli root shell'e duser (bypass grant ile root'lu).
MODDIR=/data/adb/modules
MRUN=/data/adb/ksu/mrun.sh

log() { echo "ksudshim: $1"; }

# --- module.prop helper (installer.sh ile ayni semantik) ---
grep_prop() { # $1=key $2=file
    grep -m1 "^$1=" "$2" 2>/dev/null | cut -d= -f2- | head -1
}

json_escape() {
    # stdin -> JSON string (tirnak + ters slash + newline kacar)
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}

module_json() {
    # $1 = module dir -> tek JSON objesi basar
    d="$1"
    p="$d/module.prop"
    [ -f "$p" ] || return 1
    id=$(grep_prop id "$p")
    [ -z "$id" ] && id=$(basename "$d")
    name=$(grep_prop name "$p" | json_escape)
    author=$(grep_prop author "$p" | json_escape)
    [ -z "$author" ] && author="Unknown"
    version=$(grep_prop version "$p" | json_escape)
    [ -z "$version" ] && version="Unknown"
    versionCode=$(grep_prop versionCode "$p")
    case "$versionCode" in ''|*[!0-9]*) versionCode=0 ;; esac
    description=$(grep_prop description "$p" | json_escape)
    if [ -f "$d/disable" ]; then enabled=false; else enabled=true; fi
    if [ -f "$d/update" ]; then update=true; else update=false; fi
    if [ -f "$d/remove" ]; then remove=true; else remove=false; fi
    updateJson=$(grep_prop updateJson "$p" | json_escape)
    if [ -d "$d/webroot" ]; then web=true; else web=false; fi
    if [ -f "$d/action.sh" ]; then action=true; else action=false; fi
    meta=$(grep_prop metamodule "$p")
    if [ "$meta" = "1" ] || [ "$meta" = "true" ]; then metamodule=true; else metamodule=false; fi
    printf '{"id":"%s","name":"%s","author":"%s","version":"%s","versionCode":%d,"description":"%s","enabled":%s,"update":%s,"remove":%s,"updateJson":"%s","web":%s,"action":%s,"metamodule":%s}' \
        "$id" "$name" "$author" "$version" "$versionCode" "$description" \
        "$enabled" "$update" "$remove" "$updateJson" "$web" "$action" "$metamodule"
}

cmd_module_list() {
    first=1
    printf '['
    for mod in "$MODDIR"/*; do
        [ -d "$mod" ] || continue
        obj=$(module_json "$mod") || continue
        [ "$first" = 1 ] || printf ','
        printf '%s' "$obj"
        first=0
    done
    printf ']\n'
}

cmd_module_install() {
    # $1 = zip ya da acilmis dizin (manager Java ile acar)
    if [ -d "$1" ]; then
        sh "$MRUN" install-dir "$1" "$2" || return 1
    else
        sh "$MRUN" install "$1" || return 1
    fi
    # mount-one install-dir icinde yapilir; zip yolunda id bilinmedigi
    # icin mounts yedek olarak kalir (ileride id parse edilebilir)
    sh "$MRUN" mounts
}

cmd_module_toggle() {
    # $1 = enable|disable, $2 = id
    id="$2"
    [ -d "$MODDIR/$id" ] || { log "not found: $id"; return 1; }
    if [ "$1" = "disable" ]; then
        touch "$MODDIR/$id/disable" && log "- Disabled $id"
    else
        rm -f "$MODDIR/$id/disable" && log "- Enabled $id"
    fi
}

cmd_module_action() {
    # $1 = id: action.sh'i calistir, ciktiyi akit
    id="$1"
    [ -f "$MODDIR/$id/action.sh" ] || { log "no action.sh: $id"; return 1; }
    sh "$MODDIR/$id/action.sh" 2>&1
}

case "$1" in
    debug)
        # libsu root-shell kurulumu: gercek interaktif sh ol
        # (bypass grant ile root'lu; libsu saglikli shell gorur)
        exec /system/bin/sh
        ;;
    module)
        case "$2" in
            list) cmd_module_list ;;
            install) shift 2; cmd_module_install "$1" ;;
            install-dir) shift 2; sh "$MRUN" install-dir "$1" "$2" ;;
            uninstall) shift 2; sh "$MRUN" uninstall "$1" ;;
            enable) cmd_module_toggle enable "$3" ;;
            disable) cmd_module_toggle disable "$3" ;;
            undo-uninstall) rm -f "$MODDIR/$3/remove" && log "- Undo uninstall $3" ;;
            action) cmd_module_action "$3" ;;
            config)
                log "module config not supported yet"
                return 1
                ;;
            *)
                log "unknown module command: $2"
                return 1
                ;;
        esac
        ;;
    feature|sepolicy|boot-restore|uninstall|resetprop|debug|su)
        log "not supported: $1"
        return 1
        ;;
    *)
        log "unknown command: $1"
        return 1
        ;;
esac
