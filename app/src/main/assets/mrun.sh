#!/system/bin/sh
# mrun: ksud-less module runner for o1s/HZC2.
# Kullanim: sh mrun.sh {mounts|services|mount-one <id>|install <zip>|
#   install-dir <dir> [zip]|unmount|unmount-one <id>|enable|disable <id>|
#   uninstall <id>|hint|boot}
# Kurallar (saha kanitli):
# - overlay YASAK (2 hardlockup). Yeni dosya = dizin-ayna + dir-bind.
# - root olarak script dosyasi DIREKT exec edilmez, hep `sh <dosya>`
#   (DEFEX oldurur). Bu dosyanin kendisi de oyle cagrilir.
# - post-fs-data sadece boot'taki mounts + kurulumdaki mount-one'da kosar.
MODDIR=/data/adb/modules
MIRRORDIR=/data/adb/mirror
MOUNTLIST=/data/adb/mirror/.mounted

log() { echo "mrun: $1"; }
# umask: ayna kopyalari herkesin okuyacagi sekilde (TrustManager app
# uid'iyle okur; 600 olursa depo bos gorunur!)
umask 022

dobind() {
    # $1=src $2=dst [$3=modid]: bind et + hedefi listeye yaz
    mount -o bind "$1" "$2" 2>/dev/null || { log "bind FAIL $2"; return 1; }
    if ! grep -qE "^$2([|]|$)" "$MOUNTLIST" 2>/dev/null; then
        if [ -n "$3" ]; then echo "$2|$3" >> "$MOUNTLIST"; else echo "$2" >> "$MOUNTLIST"; fi
    fi
    log "bind $2"
}

# hedef su an bagli mi? (reboot-artigi kayitlari sessizce dusurmek icin)
is_mounted() { grep -q " $1 " /proc/mounts 2>/dev/null; }

# hedefi her yerde sok (init ns + zygote ns'leri): katman katman
# cozer (stacked bind/tmpfs icin dongu), inatcida lazy.
peel_mount() {
    # $1 = hedef yol
    t="$1"
    [ -n "$t" ] || return 0
    for i in 1 2 3 4 5 6; do
        timeout 5 umount "$t" 2>/dev/null || break
    done
    timeout 5 umount -l "$t" 2>/dev/null
    ZPIDS=""
    ZPIDS=""
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        case "$pid" in *[!0-9]*) continue ;; esac
        if is_zygote_ns "$pid"; then
            [ -d "/proc/$pid" ] || continue
            timeout 8 nsenter -m -t "$pid" -- sh -c "umount '$t' 2>/dev/null; umount -l '$t' 2>/dev/null"
            ZPIDS="$ZPIDS $pid"
        fi
    done
    # calisan uygulamalarin kendi iskeleleri de bag tutar (hayalet sertifika);
    # zygote cocuklarinda da coz.
    APIDS=$(ps -A -o PID,PPID 2>/dev/null | awk -v z="$ZPIDS" 'BEGIN{n=split(z,a)} NR>1{for(i in a) if($2==a[i]) print $1}')
    for pid in $APIDS; do
        case "$pid" in *[!0-9]*|"") continue ;; esac
        [ -d "/proc/$pid" ] || continue
        timeout 8 nsenter -m -t "$pid" -- sh -c "umount '$t' 2>/dev/null; umount -l '$t' 2>/dev/null"
    done
    # hala bagliysa basarisiz say (kayit kalsin, retry)
    is_mounted "$t" && return 1
    return 0
}

# process zygote agacinda mi? (comm "main" olur; cmdline'a bakilir)
is_zygote_ns() {
    # $1 = pid; argv[0]'da zygote geciyorsa dogru
    # (olmus process yarisinda kaybolur -> once varlık bak)
    [ -e "/proc/$1/cmdline" ] || return 1
    c=$(tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | head -c 48) || return 1
    case "$c" in *zygote*) return 0 ;; *) return 1 ;; esac
}

# --- Magisk-protokol yardimcilar (installer.sh minimal) ---
ui_print() { echo "$1"; }
# abort oncesi basarisiz kurulum artiklarini temizler (liste kirlenmesin).
# ABORT_RM kurulum basinda modul dizinine kurulur.
abort() {
    echo "! $1"
    [ -n "$ABORT_RM" ] && rm -rf "$ABORT_RM" 2>/dev/null
    exit 1
}
grep_prop() { grep -m1 "^$1=" "$2" 2>/dev/null | cut -d= -f2- | head -1; }
set_perm_recursive() {
    # $1=dir $2=uid $3=gid $4=dperm $5=fperm
    find "$1" -type d 2>/dev/null | while read -r d; do chmod "$4" "$d" 2>/dev/null; chown "$2:$3" "$d" 2>/dev/null; done
    find "$1" -type f 2>/dev/null | while read -r f; do chmod "$5" "$f" 2>/dev/null; chown "$2:$3" "$f" 2>/dev/null; done
}

sys_dst() {
    # modul system/ altindaki rel yolu gercek hedefe cevir
    # (system/vendor -> /vendor gibi ozel partition eslemesi)
    case "$1" in
        vendor/*) echo "/${1}" ;;
        product/*) echo "/${1}" ;;
        system_ext/*) echo "/${1}" ;;
        odm/*) echo "/${1}" ;;
        *) echo "/system/${1}" ;;
    esac
}

# /system_ext/bin aynasi + su + busybox: PATH'te olup var olmayan
# tek dizin burasiydi (sadece hw+hwservicemanager var). su ve busybox
# buraya konunca tum shell'lerde ciplak bulunur (DEFEX: /system yolu
# oldugu icin root exec serbest). Sadece eksikse kurulur.
ensure_path_su() {
    [ -d /system_ext/bin ] || return 0
    [ -x /data/adb/ksu/bin/su ] || return 0
    mdir="$MIRRORDIR/__pathsu/system_ext/bin"
    if [ ! -e "$mdir/.mrun" ]; then
        mkdir -p "$mdir" || return 0
        cp /system_ext/bin/* "$mdir"/ 2>/dev/null
        touch "$mdir/.mrun"
    fi
    cp /data/adb/ksu/bin/su "$mdir"/su 2>/dev/null
    chmod 755 "$mdir"/su 2>/dev/null
    [ -f /data/adb/ksu/bin/busybox ] && {
        cp /data/adb/ksu/bin/busybox "$mdir"/busybox 2>/dev/null
        chmod 755 "$mdir"/busybox 2>/dev/null
    }
    grep -q " /system_ext/bin " /proc/mounts 2>/dev/null || \
        dobind "$mdir" "/system_ext/bin" "__pathsu"
}

# boot temizligi: canli bind varsa DOKUNMA (calisan sistem),
# yoksa bayat ayna/kayitlari sil (onceki boot'tan kalma).
boot_cleanup() {
    live=0
    if [ -f "$MOUNTLIST" ]; then
        while IFS='|' read -r m _id; do
            [ -n "$m" ] || continue
            if is_mounted "$m"; then live=1; break; fi
        done < "$MOUNTLIST" 2>/dev/null
    fi
    if [ "$live" = 1 ]; then
        log "boot-cleanup: live binds present, keeping mirrors"
        return 0
    fi
    log "boot-cleanup: clearing stale mirrors"
    rm -rf "${MIRRORDIR:?}/"* 2>/dev/null
    rm -f "$MOUNTLIST" 2>/dev/null
}

# APEX cacerts enjeksiyonu: init ns'ine bagla, paylasim CANLI
# yayildigi icin zygote/uygulamalar aninda gorur (kanitli).
# nsenter YOK (gereksiz + zygote'lari huzursuz ediyor olabilir).
inject_apex_cacerts() {
    need=0
    for mod in "$MODDIR"/*; do
        [ -d "$mod" ] || continue
        [ -f "$mod/disable" ] && continue
        if ls "$mod"/system/etc/security/cacerts/* 2>/dev/null | grep -q .; then
            need=1; break
        fi
    done
    [ "$need" = 1 ] || return 0
    [ -d /apex/com.android.conscrypt/cacerts ] || return 0
    log "apex cacerts inject"
    # Bind kaynagi hedef iskeletten cozulur; ayna baska ns'te yoktur.
    # O yuzden GERCEK bir staging dizini kullan (modülün tmpdir yöntemi).
    STAGE=/data/adb/ksu/cacerts-stage
    mkdir -p "$STAGE"
    # staging: mevcut gorunumdeki dosyalari kopyala (ayna icerigi dahil)
    for c in /system/etc/security/cacerts/*.0; do
        [ -f "$c" ] || continue
        b=${c##*/}
        if [ ! -f "$STAGE/$b" ] || ! cmp -s "$c" "$STAGE/$b"; then
            cp -f "$c" "$STAGE/$b" 2>/dev/null
        fi
    done
    chmod 755 "$STAGE" 2>/dev/null
    chmod 644 "$STAGE"/*.0 2>/dev/null
    # bayat temizligi: kaynakta olmayan isim staging'de kalmasin
    # (kaldirilan modulun sertifikasi hayalet olurdu)
    for s in "$STAGE"/*.0; do
        [ -f "$s" ] || continue
        [ -f "/system/etc/security/cacerts/${s##*/}" ] || rm -f "$s"
    done
    mount -o bind "$STAGE" /apex/com.android.conscrypt/cacerts 2>/dev/null \
        && log "apex-bound in init"
    # zygote iskeleleri + calisan uygulamalar (modülün APP_PIDS döngüsü)
    # pgrep piyango oldugu icin /proc taramasi kullan.
    ZPIDS=""
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        case "$pid" in *[!0-9]*) continue ;; esac
        if is_zygote_ns "$pid"; then
            ZPIDS="$ZPIDS $pid"
        fi
    done
    nsenter -m -t 1 -- mount -o bind "$STAGE" /apex/com.android.conscrypt/cacerts 2>/dev/null
    APP_PIDS=$(ps -A -o PID,PPID 2>/dev/null | awk -v z="$ZPIDS" 'BEGIN{n=split(z,a)} NR>1{for(i in a) if($2==a[i]) print $1}')
    n=0
    for pid in $ZPIDS $APP_PIDS; do
        case "$pid" in *[!0-9]*|"") continue ;; esac
        [ -d "/proc/$pid" ] || continue
        if nsenter -m -t "$pid" -- mount -o bind "$STAGE" /apex/com.android.conscrypt/cacerts 2>/dev/null; then
            n=$((n+1))
        fi
    done
    log "apex-bound in $n namespaces"
    # dogrulama: zygote'lar gercekten goruyor mu? (dogum/olum yarisi
    # enjeksiyonu iskalayabilir). bag ya hep vardir ya hic: tek
    # nobetci dosya yeterli. eksik varsa bir tur daha dene.
    miss=0
    sentinel=""
    for f in "$STAGE"/*.0; do
        [ -f "$f" ] && { sentinel=${f##*/}; break; }
    done
    if [ -n "$sentinel" ]; then
        for pid in $ZPIDS; do
            case "$pid" in *[!0-9]*|"") continue ;; esac
            [ -d "/proc/$pid" ] || continue
            if ! nsenter -m -t "$pid" -- ls "/apex/com.android.conscrypt/cacerts/$sentinel" >/dev/null 2>&1; then
                miss=$((miss+1))
                nsenter -m -t "$pid" -- mount -o bind "$STAGE" /apex/com.android.conscrypt/cacerts 2>/dev/null
            fi
        done
    fi
    [ "$miss" = 0 ] && log "apex verified in zygotes" || log "apex retry for $miss zygotes"
}

each_module() {
    # $1 = stage (post-fs-data.sh / service.sh / mounts) [$2 = modid filtresi]
    # install akisi mount-one ile tek modul calistirir (upstream semantik:
    # post-fs-data sadece boot'ta + kurulan module hemen uygulanir).
    for mod in "$MODDIR"/*; do
        [ -d "$mod" ] || continue
        [ -f "$mod/disable" ] && continue
        if [ -n "$2" ] && [ "$(basename "$mod")" != "$2" ]; then continue; fi
        case "$1" in
            mounts)
                [ -f "$mod/skip_mount" ] && continue
                [ -d "$mod/system" ] || continue
                modid=$(basename "$mod")
                # 1. asama: hedefi MEVCUT dosyalar -> file-bind
                ( cd "$mod/system" 2>/dev/null || exit 0
                  find . -type f 2>/dev/null | while read -r f; do
                      rel=${f#./}
                      dst=$(sys_dst "$rel")
                      [ -e "$dst" ] || continue
                      dobind "$mod/system/$rel" "$dst" "$modid"
                  done )
                # 2. asama: hedefi OLMAYAN dosyalar -> dizin-ayna + dir-bind
                # (ayni hedef dizindeki yeni dosyalari grupla)
                ( cd "$mod/system" 2>/dev/null || exit 0
                  find . -type f 2>/dev/null | while read -r f; do
                      rel=${f#./}
                      dst=$(sys_dst "$rel")
                      [ -e "$dst" ] && continue
                      dstdir=$(dirname "$dst")
                      [ -d "$dstdir" ] || continue
                      mdir="$MIRRORDIR/$modid$dstdir"
                      if [ ! -e "$mdir/.mrun" ]; then
                          mkdir -p "$mdir" || continue
                          cp "$dstdir"/* "$mdir"/ 2>/dev/null
                          chmod 755 "$mdir" 2>/dev/null
                          chmod 644 "$mdir"/* 2>/dev/null
                          touch "$mdir/.mrun"
                          dobind "$mdir" "$dstdir" "$modid" || continue
                      fi
                      # reboot sonrasi: ayna durur, bind gider -> tekrar bagla
                      grep -q " $dstdir " /proc/mounts 2>/dev/null \
                          || dobind "$mdir" "$dstdir" "$modid"
                      cp "$mod/system/$rel" "$mdir/" 2>/dev/null \
                          && log "mirror-add $rel" || log "mirror-add FAIL $rel"
                  done )
                ;;
            *)
                [ -x "$mod/$1" ] || [ -f "$mod/$1" ] || continue
                log "exec $mod/$1"
                sh "$mod/$1" >/dev/null 2>&1 &
                ;;
        esac
    done
}

do_install() {
    # $1 = zip: Magisk-protokol kurulum (customize.sh / install.sh destegi)
    zip="$1"
    [ -f "$zip" ] || abort "! Zip not found: $zip"
    TMPDIR=/data/local/tmp/mrun-inst
    rm -rf "$TMPDIR"; mkdir -p "$TMPDIR" || abort "! No tmp space"
    # LMK bicer diye unzip retry (kucuk islerde bile olum gozlemlendi)
    ok=0
    for i in 1 2 3 4 5 6 7 8; do
        if unzip -o -q "$zip" module.prop -d "$TMPDIR" 2>/dev/null && [ -f "$TMPDIR/module.prop" ]; then ok=1; break; fi
        sleep 1
    done
    [ "$ok" = 1 ] || abort "! Unable to extract zip file!"
    id=$(grep_prop id "$TMPDIR/module.prop")
    name=$(grep_prop name "$TMPDIR/module.prop")
    [ -n "$id" ] || abort "! No id in module.prop!"
    case "$id" in [a-zA-Z][a-zA-Z0-9._-]*) ;; *) abort "! Invalid module id: $id" ;; esac
    ui_print "- Installing $name ($id)"
    MODPATH="$MODDIR/$id"
    rm -rf "$MODPATH"; mkdir -p "$MODPATH" || abort "! Cannot create module dir"
    ABORT_RM="$MODPATH"; export ABORT_RM
    if unzip -l "$zip" 2>/dev/null | grep -q "customize.sh"; then
        # modern akis
        if unzip -o -q "$zip" customize.sh -d "$MODPATH" 2>/dev/null && grep -q '^SKIPUNZIP=1$' "$MODPATH/customize.sh" 2>/dev/null; then
            ui_print "- SKIPUNZIP: customize.sh only"
        else
            ui_print "- Extracting module files"
            ok=0
            for i in 1 2 3 4 5 6 7 8; do
                unzip -o -q "$zip" -x 'META-INF/*' -d "$MODPATH" 2>/dev/null && { ok=1; break; }
                sleep 1
            done
            [ "$ok" = 1 ] || abort "! Extract failed (LMK?)"
            set_perm_recursive "$MODPATH" 0 0 0755 0644
        fi
        if [ -f "$MODPATH/customize.sh" ]; then
            ui_print "- Running customize.sh"
            MODPATH="$MODPATH" TMPDIR="$TMPDIR" ZIPFILE="$zip" OUTFD=1 \
                KSU=true KSU_MAGIC_MOUNT=true sh "$MODPATH/customize.sh" 2>&1 \
                || abort "! customize.sh failed"
        fi
        rm -f "$MODPATH/customize.sh"
    else
        # legacy akis: install.sh + callbacks
        unzip -o -q "$zip" module.prop install.sh uninstall.sh -d "$TMPDIR" 2>/dev/null
        [ -f "$TMPDIR/install.sh" ] || abort "! No install.sh!"
        SKIPMOUNT=false; PROPFILE=false; POSTFSDATA=false; LATESTARTSERVICE=false
        print_modname() { ui_print "- $MODNAME"; }
        on_install() { return 0; }
        set_permissions() { return 0; }
        MODNAME="$name"
        . "$TMPDIR/install.sh"
        print_modname
        on_install
        [ -f "$TMPDIR/uninstall.sh" ] && cp -af "$TMPDIR/uninstall.sh" "$MODPATH/uninstall.sh"
        $SKIPMOUNT && touch "$MODPATH/skip_mount"
        $POSTFSDATA && cp -af "$TMPDIR/post-fs-data.sh" "$MODPATH/post-fs-data.sh" 2>/dev/null
        $LATESTARTSERVICE && cp -af "$TMPDIR/service.sh" "$MODPATH/service.sh" 2>/dev/null
        cp -af "$TMPDIR/module.prop" "$MODPATH/module.prop"
        # legacy dosya agaci: system/ dahil her seyi acar
        unzip -o -q "$zip" -x 'META-INF/*' 'module.prop' 'install.sh' 'uninstall.sh' -d "$MODPATH" 2>/dev/null
        set_perm_recursive "$MODPATH" 0 0 0755 0644
    fi
    rm -rf "$TMPDIR"
    ui_print "- Done"
    ABORT_RM=""; export ABORT_RM
    # yeni modul hemen uygulansin (sadece bu modul)
    sh "$0" mount-one "$id"
}

# NOT: ensure_init_ns exec'lediyse buraya donulmez (exec replace).
# Aksi halde zaten init ns'indeyiz, dogrudan devam.

ensure_init_ns() {
    [ -n "$NSENTERED" ] && return 0
    if [ "$(readlink /proc/self/ns/mnt 2>/dev/null)" != "$(readlink /proc/1/ns/mnt 2>/dev/null)" ]; then
        log "entering init mountns"
        # sh ile cagir: shebang exec (/data) DEFEX'e takilir, sh okumak guvenli
        NSENTERED=1 exec /system/bin/toybox nsenter -m -t 1 /system/bin/sh "$0" "$@"
    fi
}
case "$1" in
    mounts|services|unmount|unmount-one|mount-one|boot)
        ensure_init_ns "$@"
        ;;
esac

case "$1" in
    mounts)
        log "stage mounts"
        # Idempotency: onceki calismanin tmpfs/bind artiklarini once
        # sok (modul script'leri her kostugunda katman yigar).
        # SIRA: once mount'lar (taban), sonra post-fs-data (modul
        # script'i uzerine yazar; örn. CA modulu tmpfs+nsenter yapar).
        # Tersi (once script) script'in bind'larini gotururuyordu.
        peel_mount /system/etc/security/cacerts
        peel_mount /apex/com.android.conscrypt/cacerts
        each_module mounts
        wait
        ensure_path_su
        # adbd Load'dan once dogduysa PATH su'sunu goremez (bayat iskele);
        # sadece eksikse init'e dirilt (adb bir an duser, geri gelir).
        ADBD=$(pidof adbd 2>/dev/null | tr ' ' '\n' | head -1)
        if [ -n "$ADBD" ] && [ -d "/proc/$ADBD" ]; then
            if ! nsenter -m -t "$ADBD" -- ls /system_ext/bin/su >/dev/null 2>&1; then
                log "adbd ns stale, restarting adbd"
                kill "$ADBD" 2>/dev/null
            fi
        fi
        each_module post-fs-data.sh
        wait
        inject_apex_cacerts
        # dogrulama: beklenen bind'ler gercekten tuttu mu?
        # (LMK baskisinda sessiz olumler oluyor; gorunur kil)
        miss="$MIRRORDIR/.verify-missing"
        rm -f "$miss"; touch "$miss"
        for mod in "$MODDIR"/*; do
            [ -d "$mod" ] || continue
            [ -f "$mod/disable" ] && continue
            [ -f "$mod/skip_mount" ] && continue
            [ -d "$mod/system" ] || continue
            ( cd "$mod/system" 2>/dev/null || exit 0
              find . -type f 2>/dev/null | while read -r f; do
                  rel=${f#./}
                  dst=$(sys_dst "$rel")
                  [ -e "$dst" ] || dst=$(dirname "$dst")
                  # dosya tekil bagli degilse kapsayan dizin bagi da gecer
                  grep -q " $dst " /proc/mounts 2>/dev/null \
                      || grep -q " $(dirname "$dst") " /proc/mounts 2>/dev/null \
                      || echo "$dst" >> "$miss"
              done )
        done
        if [ -s "$miss" ]; then
            log "- WARNING: mounts that did not stick (retry or reboot):"
            cat "$miss" | head -10
        else
            log "- Mounts verified OK"
        fi
        rm -f "$miss"
        ;;
    mount-one)
        # $2 = modid: sadece o modulun mount'lari + script'i
        # (sira: mount once, script sonra - yazar kazanir)
        [ -n "$2" ] || { echo "usage: $0 mount-one <id>"; exit 1; }
        log "stage mount-one $2"
        each_module mounts "$2"
        wait
        each_module post-fs-data.sh "$2"
        wait
        inject_apex_cacerts
        ;;
    apex)
        # hafif: sadece staging tazeleyip apex enjekte et
        # (zygote restart sonrasi tazeleme icin; mirror/script'lere dokunmaz)
        log "stage apex"
        inject_apex_cacerts
        ;;
    services)
        log "stage services"
        each_module service.sh
        ;;
    install)
        [ -n "$2" ] || { echo "usage: $0 install <zip>"; exit 1; }
        do_install "$2"
        ;;
    install-dir)
        # $2 = onceden acilmis modul dizini [$3 = orijinal zip (customize ZIPFILE)]
        [ -d "$2" ] || abort "! No such directory: $2"
        [ -f "$2/module.prop" ] || abort "! No module.prop!"
        id=$(grep_prop id "$2/module.prop")
        [ -n "$id" ] || abort "! No id in module.prop!"
        case "$id" in [a-zA-Z][a-zA-Z0-9._-]*) ;; *) abort "! Invalid module id: $id" ;; esac
        name=$(grep_prop name "$2/module.prop")
        ui_print "- Installing $name ($id)"
        MODPATH="$MODDIR/$id"
        rm -rf "$MODPATH"; mkdir -p "$MODPATH" || abort "! Cannot create module dir"
    ABORT_RM="$MODPATH"; export ABORT_RM
        cp -af "$2"/* "$MODPATH"/ 2>/dev/null
        cp -af "$2"/.git* "$MODPATH"/ 2>/dev/null
        rm -f "$MODPATH/customize.sh"
        set_perm_recursive "$MODPATH" 0 0 0755 0644
        if [ -f "$2/customize.sh" ]; then
            ui_print "- Running customize.sh"
            MODPATH="$MODPATH" TMPDIR="$2" ZIPFILE="${3:-$2}" OUTFD=1 \
                KSU=true KSU_MAGIC_MOUNT=true sh "$2/customize.sh" 2>&1 \
                || abort "! customize.sh failed"
        elif [ -f "$2/install.sh" ]; then
            ui_print "- Running install.sh (legacy)"
            SKIPMOUNT=false; PROPFILE=false; POSTFSDATA=false; LATESTARTSERVICE=false
            print_modname() { ui_print "- $MODNAME"; }
            on_install() { return 0; }
            set_permissions() { return 0; }
            MODNAME="$name"; MODPATH="$MODPATH"; TMPDIR="$2"
            . "$2/install.sh"
            print_modname
            on_install
        fi
        ui_print "- Done"
    ABORT_RM=""; export ABORT_RM
        # yeni modul hemen uygulansin (sadece bu modul; digerlerine
        # dokunulmaz - upstream semantik). Tum modul mount'lari
        # sadece boot'taki mounts asamasinda calisir.
        sh "$0" mount-one "$id"
        ;;
    hint)
        # manager APK yolunu taht ipucuna yaz (paket yoksa sessiz cik)
        P=$(cmd package path me.weishu.kernelsu 2>/dev/null | cut -d: -f2)
        [ -n "$P" ] || exit 0
        echo "$P" > /data/adb/ksu/.manager_apk && log "hint: $P"
        # libadbroot.so'yu manager lib'inden senkronla (ADB Root onkosulu)
        L=$(dirname "$P")/lib/arm64/libadbroot.so
        if [ -f "$L" ]; then
            mkdir -p /data/adb/ksu/lib
            cp "$L" /data/adb/ksu/lib/libadbroot.so 2>/dev/null
            chmod 755 /data/adb/ksu/lib/libadbroot.so 2>/dev/null
        fi
        ;;
    boot)
        # boot zinciri girisi: temizlik + mounts + services (+ PATH su)
        log "stage boot"
        boot_cleanup
        ensure_path_su
        sh "$0" mounts
        sh "$0" services
        ;;
    unmount)
        # hepsi: SADECE bizim listemizdekileri coz
        # bagli OLMAYAN kayitlar sessizce duser (reboot artigi)
        # basarisizlar listede kalir (retry icin)
        # + paylasilan cacerts her iskelette sokulur (oksuz bind'ler icin)
        peel_mount /system/etc/security/cacerts
        peel_mount /apex/com.android.conscrypt/cacerts
        [ -f "$MOUNTLIST" ] || { log "nothing mounted"; exit 0; }
        tmp="$MOUNTLIST.new"
        rm -f "$tmp"; touch "$tmp"
        while IFS='|' read -r m _id; do
            [ -n "$m" ] || continue
            is_mounted "$m" || continue
            peel_mount "$m" && log "unmounted $m" || {
                echo "$m${_id:+|$_id}" >> "$tmp"
                log "unmount FAILED (kept) $m"
            }
        done < "$MOUNTLIST"
        mv "$tmp" "$MOUNTLIST"
        ;;
    unmount-one)
        # $2 = modid: sadece o modulun bind'lerini coz
        [ -f "$MOUNTLIST" ] || exit 0
        tmp="$MOUNTLIST.new"
        rm -f "$tmp"; touch "$tmp"
        while IFS='|' read -r m mid; do
            [ -n "$m" ] || continue
            if [ "$mid" = "$2" ]; then
                is_mounted "$m" || continue
                peel_mount "$m" && log "unmounted $m" || {
                    echo "$m|$mid" >> "$tmp"
                    log "unmount FAILED (kept) $m"
                }
            else
                echo "$m${mid:+|$mid}" >> "$tmp"
            fi
        done < "$MOUNTLIST"
        mv "$tmp" "$MOUNTLIST"
        ;;
    enable|disable)
        # $2 = modid
        [ -d "$MODDIR/$2" ] || { log "not found: $2"; exit 1; }
        if [ "$1" = "disable" ]; then touch "$MODDIR/$2/disable"; else rm -f "$MODDIR/$2/disable"; fi
        log "$1d $2"
        ;;
    uninstall)
        # $2 = modid: uninstall.sh + bind coz + sil
        [ -d "$MODDIR/$2" ] || { log "not found: $2"; exit 1; }
        if [ -f "$MODDIR/$2/uninstall.sh" ]; then
            log "- Running uninstall.sh"
            sh "$MODDIR/$2/uninstall.sh" 2>&1 | head -20
        fi
        # modul cacerts tasiyorsa ve baska hicbir etkin modul
        # tasimiyorsa, paylasilan cacerts bind'lerini de sok
        # (modul script'lerinin takipsiz bind'leri dahil)
        had_ca=0
        ls "$MODDIR/$2"/system/etc/security/cacerts/* 2>/dev/null | grep -q . && had_ca=1
        sh "$0" unmount-one "$2"
        rm -rf "$MODDIR/$2" "$MIRRORDIR/$2"
        if [ "$had_ca" = 1 ]; then
            other_ca=0
            for mod in "$MODDIR"/*; do
                [ -d "$mod" ] || continue
                [ -f "$mod/disable" ] && continue
                ls "$mod"/system/etc/security/cacerts/* 2>/dev/null | grep -q . && { other_ca=1; break; }
            done
            if [ "$other_ca" = 0 ]; then
                log "- Peeling shared cacerts binds"
                peel_mount /system/etc/security/cacerts
                peel_mount /apex/com.android.conscrypt/cacerts
                if grep -q "cacerts" /proc/mounts 2>/dev/null; then
                    log "- WARNING: stale cacerts binds remain (close apps using them, retry uninstall)"
                fi
            fi
        fi
        log "- Uninstalled $2"
        ;;
    *)
        echo "usage: $0 {mounts|apex|services|install <zip>|install-dir <dir> [zip]|unmount|unmount-one <id>|mount-one <id>|enable|disable|uninstall <id>|hint|boot}"
        exit 1
        ;;
esac
