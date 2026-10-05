#!/system/bin/sh
# deploy.sh: DFRoot asset'lerini hedeflere dagitir (tek sudShell cagrisi).
# Cagrilma: sh /data/user_de/0/df.root/deploy.sh
# 70-karakter sudShell sinirina takilmamak icin toplu is burada.
S=/data/user_de/0/df.root
D=/data/adb/ksu
log() { echo "deploy: $1"; }
cp "$S/mrun.sh" "$S/ksudshim.sh" "$D/" 2>/dev/null
chmod 755 "$D/mrun.sh" "$D/ksudshim.sh" 2>/dev/null
mkdir -p "$D/bin"
cp "$S/su" "$D/bin/su" 2>/dev/null
cp "$S/ksud" "$D/bin/ksud" 2>/dev/null
cp "$S/ksudrain" "$D/bin/ksudrain" 2>/dev/null
cp "$S/ksuev" "$D/bin/ksuev" 2>/dev/null
cp "$S/busybox" "$D/bin/busybox" 2>/dev/null
chmod 755 "$D/bin/su" "$D/bin/ksud" "$D/bin/ksudrain" "$D/bin/ksuev" "$D/bin/busybox" 2>/dev/null
chmod 755 "$D" "$D/bin" 2>/dev/null
chmod 755 /data/adb 2>/dev/null
ln -sf "$D/bin/ksud" /data/adb/ksud 2>/dev/null
sh "$D/mrun.sh" hint 2>/dev/null
log "done"
