#!/system/bin/sh
LOG=/data/local/tmp/script.log
BOOTLOOP_PROTECTION=1
HIDE_ADS=0

echo "Script started at $(date)" > $LOG
chmod 666 $LOG

if [ "$BOOTLOOP_PROTECTION" = "1" ]; then
    if [ -f /data/local/tmp/start ]; then
        echo "$(date): /data/local/tmp/start exists — previous boot did NOT complete. Script aborted, doing nothing." >> $LOG
        exit 1
    fi
    touch /data/local/tmp/start
    echo "$(date): marker created: /data/local/tmp/start" >> $LOG
else
    echo "$(date): BOOTLOOP_PROTECTION=0 — skipping marker check, running script" >> $LOG
fi

if ! strings /dev/block/misc | grep -q 'myinit-max'; then
    echo "$(date): misc NOT patched, flashing misc.img" >> $LOG
    dd if=/data/local/tmp/misc.img of=/dev/block/misc &>> $LOG
    sync
else
    echo "$(date): misc already patched (myinit-max), skipping dd" >> $LOG
fi

BIN_DIR=/data/local/tmp/bin

mount -o bind /data/local/tmp/bin /sbin &>> $LOG

if /sbin/sepolicy-inject -f /data/local/tmp/sepolicy.rule -l >/dev/null 2>&1; then
    umount /sys/fs/selinux/enforce
    echo 1 > /sys/fs/selinux/enforce
else
    echo "sepolicy-inject failed, skipping seting selinux" &>> $LOG
fi

resetprop ro.boot.vbmeta.device_state locked &>> $LOG
resetprop ro.boot.selinux enforcing &>> $LOG
resetprop -p -d persist.adb.root &>> $LOG
resetprop -p -d persist.adb.tcp.port &>> $LOG

# /sbin/sepolicy-inject -Z kernel -l &>> $LOG

# adb root
setsid /sbin/adbd </dev/null >/dev/null 2>&1 &

# --- install new mitmproxy root CA via bind mount ---
CERT_SRC=/data/local/tmp/quasar.yandex.ru.root.crt
CERTS_DIR=/data/local/tmp/certs
CERT_NAME=c8750f0d.0

if [ "$HIDE_ADS" = "1" ]; then
    if mount | grep -q ' /system/etc/security/cacerts '; then
        echo "bind mount for /system/etc/security/cacerts already active, skipping" >> $LOG
    else
        echo "Setting up bind mount for /system/etc/security/cacerts" >> $LOG

        # 1. recreate directory (old content not needed)
        rm -rf "$CERTS_DIR"
        mkdir -p "$CERTS_DIR"

        # 2. copy the whole system trust store
        cp -a /system/etc/security/cacerts/. "$CERTS_DIR"/

        # 3. place our root CA under the correct name
        cp "$CERT_SRC" "$CERTS_DIR/$CERT_NAME"
        chmod 644 "$CERTS_DIR/$CERT_NAME"

        # 4. verify cert
        if command -v openssl >/dev/null 2>&1; then
            openssl x509 -in "$CERTS_DIR/$CERT_NAME" -noout -subject -dates >> $LOG 2>&1 \
                || echo "WARNING: cert check failed for $CERTS_DIR/$CERT_NAME" >> $LOG
        fi

        # 5. bind mount
        if mount --bind "$CERTS_DIR" /system/etc/security/cacerts; then
            echo "bind mount OK: $CERTS_DIR -> /system/etc/security/cacerts" >> $LOG
        else
            echo "ERROR: bind mount failed" >> $LOG
        fi
    fi
else
    echo "HIDE_ADS is not 1, skipping certs bind mount" >> $LOG
fi

# Wait for boot to complete
until [ "$(getprop sys.boot_completed)" ]
do
 sleep 1
done
echo "Booted at $(date)" >> $LOG

if [ "$HIDE_ADS" = "1" ]; then
    setsid /sbin/tls_proxy </dev/null >/dev/null 2>&1 &

    iptables -t nat -A OUTPUT -p tcp -d 213.180.193.230 --dport 443 \
        -m owner ! --uid-owner 0 -j REDIRECT --to-ports 8443

    iptables -t nat -A OUTPUT -p tcp -d 77.88.21.175 --dport 443 \
        -m owner ! --uid-owner 0 -j REDIRECT --to-ports 8444
fi

setsid /sbin/sudo --daemon </dev/null >/dev/null 2>&1 &

configure_network_access() {
    ALLOWED_IPS="!127.0.0.1"
    PORTS="5555"

    echo "Allowed IPs: $ALLOWED_IPS, localhost only for root" >> "$LOG"

    # Detect whether any inverted IPs are present (blacklist mode)
    BLACKLIST_MODE=0
    for IP in $ALLOWED_IPS; do
        case "$IP" in
            '!'*) BLACKLIST_MODE=1 ;;
        esac
    done

    for PORT in $PORTS; do
        # Remove old rules (all possible variants)
        # Remove final DROP/ACCEPT rules for the port
        iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null && \
            iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null
        iptables -C INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null && \
            iptables -D INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null

        # Remove root@localhost rule
        iptables -C INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -m owner --uid-owner 0 -j ACCEPT 2>/dev/null && \
            iptables -D INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -m owner --uid-owner 0 -j ACCEPT 2>/dev/null

        # Remove localhost DROP rule
        iptables -C INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -j DROP 2>/dev/null && \
            iptables -D INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -j DROP 2>/dev/null

        # Remove rules for each IP (both with and without "!")
        for IP in $ALLOWED_IPS; do
            CLEAN_IP="${IP#!}"
            iptables -C INPUT -p tcp --dport "$PORT" -s "$CLEAN_IP" -j ACCEPT 2>/dev/null && \
                iptables -D INPUT -p tcp --dport "$PORT" -s "$CLEAN_IP" -j ACCEPT 2>/dev/null
            iptables -C INPUT -p tcp --dport "$PORT" -s "$CLEAN_IP" -j DROP 2>/dev/null && \
                iptables -D INPUT -p tcp --dport "$PORT" -s "$CLEAN_IP" -j DROP 2>/dev/null
        done

        # Add new rules
        # root from localhost is always allowed
        iptables -A INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -m owner --uid-owner 0 -j ACCEPT 2>> "$LOG"

        if [ "$BLACKLIST_MODE" -eq 1 ]; then
            # BLACKLIST MODE
            # Block all other localhost traffic (non-root)
            iptables -A INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -j DROP 2>> "$LOG"

            # First allow "plain" IPs from the list
            for IP in $ALLOWED_IPS; do
                case "$IP" in
                    '!'*) ;;  # skip, handled below
                    *) iptables -A INPUT -p tcp --dport "$PORT" -s "$IP" -j ACCEPT 2>> "$LOG" ;;
                esac
            done

            # Then block inverted IPs
            for IP in $ALLOWED_IPS; do
                case "$IP" in
                    '!'*) CLEAN_IP="${IP#!}"
                          iptables -A INPUT -p tcp --dport "$PORT" -s "$CLEAN_IP" -j DROP 2>> "$LOG" ;;
                esac
            done

            # IMPORTANT: no final DROP — all other IPs are allowed
        else
            # WHITELIST MODE (original behavior)
            iptables -A INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -j DROP 2>> "$LOG"
            for IP in $ALLOWED_IPS; do
                iptables -A INPUT -p tcp --dport "$PORT" -s "$IP" -j ACCEPT 2>> "$LOG"
            done
            iptables -A INPUT -p tcp --dport "$PORT" -j DROP 2>> "$LOG"
        fi

        # OUTPUT rules
        iptables -C OUTPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null && \
            iptables -D OUTPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null
        iptables -C OUTPUT -p tcp --dport "$PORT" -m owner --uid-owner 0 -j ACCEPT 2>/dev/null && \
            iptables -D OUTPUT -p tcp --dport "$PORT" -m owner --uid-owner 0 -j ACCEPT 2>/dev/null
        iptables -A OUTPUT -p tcp --dport "$PORT" -m owner --uid-owner 0 -j ACCEPT 2>> "$LOG"
        iptables -A OUTPUT -p tcp --dport "$PORT" -j DROP 2>> "$LOG"
}

configure_network_access &

# wait some time so wifi is certainly connected, then restart io sdk to reload config caches
if [ "$HIDE_ADS" = "1" ]; then
    ( sleep 50; killall -9 com.yandex.io.sdk ) &
fi
# wait some more so quasar applied its config with ADB disabled, then turn on ADB
# (sleep 60; setprop service.adb.tcp.port 5555; setprop sys.usb.config adb; setprop persist.sys.usb.config adb) & # Enable it if adbd is not working

if [ "$BOOTLOOP_PROTECTION" = "1" ]; then
    rm -f /data/local/tmp/start
    echo "$(date): marker removed: /data/local/tmp/start" >> $LOG
else
    echo "$(date): BOOTLOOP_PROTECTION=0 — marker removal skipped" >> $LOG
fi

dmesg -n 3
