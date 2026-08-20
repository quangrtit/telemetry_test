#!/bin/sh
# linux_security_inventory.sh
# Read-only Linux inventory collector for:
#   - distro / kernel / architecture
#   - Secure Boot state
#   - Kaspersky-related running processes
#   - Falco running processes and driver mode (kmod / modern eBPF / legacy eBPF)
#
# Design goals:
#   * POSIX /bin/sh (no bashisms)
#   * no package installation
#   * no module/BPF load/unload/attach/detach
#   * no dmesg access required
#   * no full process argv/environment is emitted (avoids leaking secrets)
#   * graceful degradation when procfs/sysfs/config permissions are restricted

set -u
LC_ALL=C
export LC_ALL
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

TOOL_VERSION="1.0.0"

have() { command -v "$1" >/dev/null 2>&1; }

# JSON escape for the small, line-oriented values emitted by this collector.
# Control characters are normalized before values reach this function.
json_escape() {
    printf '%s' "$1" | awk 'BEGIN { ORS="" }
        {
            if (NR > 1) printf "\\n"
            gsub(/\\/, "\\\\")
            gsub(/\"/, "\\\"")
            gsub(/\t/, "\\t")
            gsub(/\r/, "\\r")
            printf "%s", $0
        }'
}

jstr() {
    printf '"'
    json_escape "$1"
    printf '"'
}

# Read KEY=VALUE from os-release WITHOUT sourcing/eval'ing the file.
os_release_value() {
    _file=$1
    _key=$2
    awk -F= -v k="$_key" '
        $1 == k {
            v=substr($0, index($0, "=")+1)
            if (v ~ /^".*"$/) {
                v=substr(v, 2, length(v)-2)
                gsub(/\\"/, "\"", v)
                gsub(/\\\\/, "\\", v)
            } else if (v ~ /^\047.*\047$/) {
                v=substr(v, 2, length(v)-2)
            }
            print v
            exit
        }' "$_file" 2>/dev/null
}

get_distro() {
    DISTRO_ID="unknown"
    DISTRO_VERSION="unknown"
    DISTRO_PRETTY="unknown"
    DISTRO_SOURCE="fallback"

    _osr=""
    if [ -r /etc/os-release ]; then
        _osr=/etc/os-release
    elif [ -r /usr/lib/os-release ]; then
        _osr=/usr/lib/os-release
    fi

    if [ -n "$_osr" ]; then
        _v=$(os_release_value "$_osr" ID)
        [ -n "$_v" ] && DISTRO_ID=$_v
        _v=$(os_release_value "$_osr" VERSION_ID)
        [ -n "$_v" ] && DISTRO_VERSION=$_v
        _v=$(os_release_value "$_osr" PRETTY_NAME)
        [ -n "$_v" ] && DISTRO_PRETTY=$_v
        DISTRO_SOURCE=$_osr
        return
    fi

    if have lsb_release; then
        _v=$(lsb_release -si 2>/dev/null | head -n 1)
        [ -n "$_v" ] && DISTRO_ID=$_v
        _v=$(lsb_release -sr 2>/dev/null | head -n 1)
        [ -n "$_v" ] && DISTRO_VERSION=$_v
        _v=$(lsb_release -sd 2>/dev/null | head -n 1 | sed 's/^"//;s/"$//')
        [ -n "$_v" ] && DISTRO_PRETTY=$_v
        DISTRO_SOURCE="lsb_release"
        return
    fi

    for _f in /etc/redhat-release /etc/centos-release /etc/oracle-release \
              /etc/alpine-release /etc/debian_version /etc/SuSE-release \
              /etc/gentoo-release; do
        if [ -r "$_f" ]; then
            _v=$(head -n 1 "$_f" 2>/dev/null | tr '\t\r\n' '   ')
            [ -n "$_v" ] && DISTRO_PRETTY=$_v
            DISTRO_SOURCE=$_f
            break
        fi
    done
}

detect_container() {
    IN_CONTAINER=0
    if [ -e /.dockerenv ] || [ -e /run/.containerenv ]; then
        IN_CONTAINER=1
        return
    fi
    if [ -r /proc/1/cgroup ] && grep -Eiq '(docker|containerd|kubepods|lxc|podman)' /proc/1/cgroup 2>/dev/null; then
        IN_CONTAINER=1
    fi
}

get_secure_boot() {
    SECURE_BOOT="unknown"
    SECURE_BOOT_SOURCE="none"
    SECURE_BOOT_DETAIL=""

    # mokutil is the clearest user-space interface when installed.
    if have mokutil; then
        _out=$(mokutil --sb-state 2>/dev/null | head -n 2 | tr '\r\n' '  ')
        case "$_out" in
            *"SecureBoot enabled"*|*"Secure Boot enabled"*)
                SECURE_BOOT="enabled"
                SECURE_BOOT_SOURCE="mokutil"
                SECURE_BOOT_DETAIL="$_out"
                return
                ;;
            *"SecureBoot disabled"*|*"Secure Boot disabled"*)
                SECURE_BOOT="disabled"
                SECURE_BOOT_SOURCE="mokutil"
                SECURE_BOOT_DETAIL="$_out"
                return
                ;;
        esac
    fi

    # No EFI firmware exposed on a host means Secure Boot is not active for this boot.
    # In a container, however, host EFI state is commonly hidden, so do not claim disabled.
    if [ ! -d /sys/firmware/efi ]; then
        if [ "${IN_CONTAINER:-0}" -eq 1 ]; then
            SECURE_BOOT="unknown"
            SECURE_BOOT_SOURCE="container_efi_not_visible"
            SECURE_BOOT_DETAIL="container does not expose host EFI SecureBoot state"
        else
            SECURE_BOOT="disabled"
            SECURE_BOOT_SOURCE="no_efi_firmware"
            SECURE_BOOT_DETAIL="system is not booted with EFI firmware"
        fi
        return
    fi

    # efivarfs stores 4 bytes of attributes followed by the variable payload.
    # SecureBoot payload is normally one byte: 1 = enabled, 0 = disabled.
    if have od; then
        for _f in /sys/firmware/efi/efivars/SecureBoot-*; do
            [ -r "$_f" ] || continue
            _byte=$(od -An -tu1 -j4 -N1 "$_f" 2>/dev/null | tr -d '[:space:]')
            case "$_byte" in
                1)
                    SECURE_BOOT="enabled"
                    SECURE_BOOT_SOURCE="efivarfs"
                    SECURE_BOOT_DETAIL="SecureBoot EFI variable = 1"
                    return
                    ;;
                0)
                    SECURE_BOOT="disabled"
                    SECURE_BOOT_SOURCE="efivarfs"
                    SECURE_BOOT_DETAIL="SecureBoot EFI variable = 0"
                    return
                    ;;
            esac
        done
    fi

    SECURE_BOOT="unknown"
    SECURE_BOOT_SOURCE="efi_present_but_unreadable"
    SECURE_BOOT_DETAIL="EFI is present, but SecureBoot state could not be read"
}

proc_mount_visibility() {
    PROC_VISIBILITY="normal_or_unknown"
    if [ "$(id -u 2>/dev/null || printf '1')" = "0" ]; then
        PROC_VISIBILITY="root"
        return
    fi
    if [ -r /proc/mounts ]; then
        _opts=$(awk '$2=="/proc" {print $4; exit}' /proc/mounts 2>/dev/null)
        case ",$_opts," in
            *,hidepid=2,*|*,hidepid=invisible,*) PROC_VISIBILITY="restricted_hidepid2" ;;
            *,hidepid=1,*|*,hidepid=noaccess,*) PROC_VISIBILITY="restricted_hidepid1" ;;
        esac
    fi
}

safe_readlink() {
    if have readlink; then
        readlink "$1" 2>/dev/null || printf ''
    else
        printf ''
    fi
}

proc_exe_base() {
    _pid=$1
    _exe=$(safe_readlink "/proc/$_pid/exe")
    if [ -n "$_exe" ]; then
        basename "$_exe" 2>/dev/null || printf '%s' "$_exe"
    else
        printf ''
    fi
}

proc_comm() {
    _pid=$1
    if [ -r "/proc/$_pid/comm" ]; then
        head -n 1 "/proc/$_pid/comm" 2>/dev/null | tr '\t\r\n' '   ' | sed 's/[[:space:]]*$//'
    elif [ -r "/proc/$_pid/stat" ]; then
        # Best-effort fallback only. comm may contain ')' so this is deliberately not
        # used when /proc/PID/comm exists.
        sed -n 's/^[0-9][0-9]* (\(.*\)) .*/\1/p' "/proc/$_pid/stat" 2>/dev/null | head -n 1
    fi
}

is_kaspersky_process() {
    _comm=$1
    _base=$2
    _exe=$3
    case "$_comm" in
        kesl|kesl-*|klnagent|klnagent-*|kav4fs|kav4fs-*|kaspersky|kaspersky-*) return 0 ;;
    esac
    case "$_base" in
        kesl|kesl-*|klnagent|klnagent-*|kav4fs|kav4fs-*|kaspersky|kaspersky-*) return 0 ;;
    esac
    case "$_exe" in
        /opt/kaspersky/*|/usr/local/kaspersky/*) return 0 ;;
    esac
    return 1
}

is_falco_process() {
    _comm=$1
    _base=$2
    _exe=$3
    case "$_comm" in
        falco) return 0 ;;
    esac
    case "$_base" in
        falco) return 0 ;;
    esac
    case "$_exe" in
        */falco) return 0 ;;
    esac
    return 1
}

falco_cli_mode_and_config() {
    _pid=$1
    FALCO_CLI_MODE=""
    FALCO_CFG_PATH=""

    [ -r "/proc/$_pid/cmdline" ] || return

    # Read NUL-separated argv one item per line. Do not emit argv to output.
    # We only extract known Falco mode/config tokens.
    tr '\000' '\n' < "/proc/$_pid/cmdline" 2>/dev/null | awk '
        BEGIN { prev="" }
        {
            arg=$0
            if (prev == "config") { print "CFG=" arg; prev=""; next }
            if (arg == "-c" || arg == "--config") { prev="config"; next }
            if (arg ~ /^--config=/) { sub(/^--config=/, "", arg); print "CFG=" arg; next }
            if (arg == "--modern-bpf" || arg == "--modern_ebpf") print "MODE=modern_ebpf"
            if (arg ~ /^engine\.kind=modern_ebpf$/) print "MODE=modern_ebpf"
            if (arg ~ /^engine\.kind=ebpf$/) print "MODE=legacy_ebpf"
            if (arg ~ /^engine\.kind=kmod$/) print "MODE=kernel_module"
            if (arg == "-o") { prev="override"; next }
            if (prev == "override") {
                if (arg == "engine.kind=modern_ebpf") print "MODE=modern_ebpf"
                else if (arg == "engine.kind=ebpf") print "MODE=legacy_ebpf"
                else if (arg == "engine.kind=kmod") print "MODE=kernel_module"
                prev=""
            }
        }' > "$TMPDIR_SAFE/falco.argv.$_pid" || :

    if [ -r "$TMPDIR_SAFE/falco.argv.$_pid" ]; then
        FALCO_CLI_MODE=$(sed -n 's/^MODE=//p' "$TMPDIR_SAFE/falco.argv.$_pid" | tail -n 1)
        FALCO_CFG_PATH=$(sed -n 's/^CFG=//p' "$TMPDIR_SAFE/falco.argv.$_pid" | tail -n 1)
        rm -f "$TMPDIR_SAFE/falco.argv.$_pid" 2>/dev/null || :
    fi
}

falco_env_has_legacy_bpf() {
    _pid=$1
    [ -r "/proc/$_pid/environ" ] || return 1
    # Presence matters for older Falco; value is intentionally never emitted.
    tr '\000' '\n' < "/proc/$_pid/environ" 2>/dev/null | grep '^FALCO_BPF_PROBE=' >/dev/null 2>&1
}

falco_config_mode() {
    _cfg=$1
    [ -n "$_cfg" ] || return
    [ -r "$_cfg" ] || return

    # Supports modern Falco YAML:
    # engine:
    #   kind: modern_ebpf|ebpf|kmod
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*engine:[[:space:]]*($|#)/ { in_engine=1; next }
        in_engine {
            if ($0 ~ /^[^[:space:]#]/) { in_engine=0; next }
            if ($0 ~ /^[[:space:]]+kind:[[:space:]]*/) {
                x=$0
                sub(/^[[:space:]]+kind:[[:space:]]*/, "", x)
                sub(/[[:space:]]*#.*/, "", x)
                gsub(/["\047]/, "", x)
                gsub(/[[:space:]]/, "", x)
                print x
                exit
            }
        }' "$_cfg" 2>/dev/null
}

falco_fd_evidence() {
    _pid=$1
    FALCO_HAS_DEV_FALCO=0
    FALCO_HAS_BPF_FD=0
    FALCO_BPF_FD_COUNT=0
    FALCO_DEV_FALCO_FD_COUNT=0

    [ -d "/proc/$_pid/fd" ] || return
    for _fd in /proc/"$_pid"/fd/*; do
        [ -e "$_fd" ] || [ -L "$_fd" ] || continue
        _t=$(safe_readlink "$_fd")
        _is_bpf=0
        case "$_t" in
            /dev/falco*|*/dev/falco*)
                FALCO_HAS_DEV_FALCO=1
                FALCO_DEV_FALCO_FD_COUNT=$((FALCO_DEV_FALCO_FD_COUNT + 1))
                ;;
            *bpf-prog*|*bpf-map*|*bpf-link*)
                _is_bpf=1
                ;;
        esac

        # Some kernels expose BPF metadata in fdinfo even when readlink text is generic.
        _fdn=${_fd##*/}
        if [ "$_is_bpf" -eq 0 ] && [ -r "/proc/$_pid/fdinfo/$_fdn" ] && \
           grep -Eq '^(prog_id|map_id|link_id):' "/proc/$_pid/fdinfo/$_fdn" 2>/dev/null; then
            _is_bpf=1
        fi
        if [ "$_is_bpf" -eq 1 ]; then
            FALCO_HAS_BPF_FD=1
            FALCO_BPF_FD_COUNT=$((FALCO_BPF_FD_COUNT + 1))
        fi
    done
}

module_loaded() {
    _m=$1
    if [ -d "/sys/module/$_m" ]; then
        return 0
    fi
    if [ -r /proc/modules ] && awk -v m="$_m" '$1==m {found=1; exit} END {exit !found}' /proc/modules 2>/dev/null; then
        return 0
    fi
    return 1
}

# Resolve Falco mode per PID using strongest runtime evidence first.
resolve_falco_mode() {
    _pid=$1
    FALCO_MODE="unknown"
    FALCO_MODE_CONFIDENCE="low"
    FALCO_MODE_EVIDENCE=""
    FALCO_CONFIG_MODE=""

    falco_cli_mode_and_config "$_pid"
    falco_fd_evidence "$_pid"

    # If no explicit config was passed, try common host paths only.
    if [ -z "$FALCO_CFG_PATH" ]; then
        for _c in /etc/falco/falco.yaml /usr/local/etc/falco/falco.yaml; do
            if [ -r "$_c" ]; then
                FALCO_CFG_PATH=$_c
                break
            fi
        done
    fi
    if [ -n "$FALCO_CFG_PATH" ]; then
        FALCO_CONFIG_MODE=$(falco_config_mode "$FALCO_CFG_PATH")
    fi

    if [ "$FALCO_HAS_DEV_FALCO" -eq 1 ]; then
        FALCO_MODE="kernel_module"
        FALCO_MODE_CONFIDENCE="high"
        FALCO_MODE_EVIDENCE="falco process has open /dev/falco* fd"
        return
    fi

    if [ -n "$FALCO_CLI_MODE" ]; then
        FALCO_MODE="$FALCO_CLI_MODE"
        FALCO_MODE_CONFIDENCE="high"
        FALCO_MODE_EVIDENCE="explicit Falco command-line engine selection"
        return
    fi

    if falco_env_has_legacy_bpf "$_pid"; then
        FALCO_MODE="legacy_ebpf"
        FALCO_MODE_CONFIDENCE="high"
        FALCO_MODE_EVIDENCE="FALCO_BPF_PROBE is present in Falco environment"
        return
    fi

    case "$FALCO_CONFIG_MODE" in
        modern_ebpf)
            FALCO_MODE="modern_ebpf"
            FALCO_MODE_CONFIDENCE="medium"
            FALCO_MODE_EVIDENCE="engine.kind from readable Falco config"
            return
            ;;
        ebpf)
            FALCO_MODE="legacy_ebpf"
            FALCO_MODE_CONFIDENCE="medium"
            FALCO_MODE_EVIDENCE="engine.kind from readable Falco config"
            return
            ;;
        kmod)
            FALCO_MODE="kernel_module"
            FALCO_MODE_CONFIDENCE="medium"
            FALCO_MODE_EVIDENCE="engine.kind from readable Falco config"
            return
            ;;
    esac

    if [ "$FALCO_HAS_BPF_FD" -eq 1 ]; then
        FALCO_MODE="ebpf_unknown"
        FALCO_MODE_CONFIDENCE="medium"
        FALCO_MODE_EVIDENCE="Falco owns BPF-related fd(s), exact eBPF generation not proven"
        return
    fi

    if module_loaded falco; then
        FALCO_MODE="unknown"
        FALCO_MODE_CONFIDENCE="low"
        FALCO_MODE_EVIDENCE="falco kernel module is loaded globally, but this PID was not proven to use it"
    else
        FALCO_MODE="unknown"
        FALCO_MODE_CONFIDENCE="low"
        FALCO_MODE_EVIDENCE="no decisive runtime evidence available with current permissions"
    fi
}

mk_tmpdir() {
    _base=${TMPDIR:-/tmp}
    if have mktemp; then
        TMPDIR_SAFE=$(mktemp -d "$_base/linux-sec-inventory.XXXXXX" 2>/dev/null) || TMPDIR_SAFE=""
    else
        TMPDIR_SAFE=""
    fi
    if [ -z "$TMPDIR_SAFE" ]; then
        TMPDIR_SAFE="$_base/linux-sec-inventory.$$"
        (umask 077 && mkdir "$TMPDIR_SAFE") 2>/dev/null || {
            printf '%s\n' "ERROR: cannot create a private temporary directory" >&2
            exit 1
        }
    fi
}

cleanup() {
    [ -n "${TMPDIR_SAFE:-}" ] && rm -rf "$TMPDIR_SAFE" 2>/dev/null || :
}

mk_tmpdir
trap cleanup EXIT HUP INT TERM

get_distro
detect_container
get_secure_boot
proc_mount_visibility

HOSTNAME_VAL=$(hostname 2>/dev/null || uname -n 2>/dev/null || printf 'unknown')
KERNEL_RELEASE=$(uname -r 2>/dev/null || printf 'unknown')
KERNEL_VERSION=$(uname -v 2>/dev/null || printf 'unknown')
ARCH=$(uname -m 2>/dev/null || printf 'unknown')

FALCO_KMOD_LOADED=false
module_loaded falco && FALCO_KMOD_LOADED=true

KASP_FILE="$TMPDIR_SAFE/kaspersky.tsv"
FALCO_FILE="$TMPDIR_SAFE/falco.tsv"
: > "$KASP_FILE"
: > "$FALCO_FILE"
US=$(printf '\037')

PROC_SCAN_ERRORS=0
PROC_SCAN_COUNT=0

for _p in /proc/[0-9]*; do
    [ -d "$_p" ] || continue
    _pid=${_p##*/}
    _comm=$(proc_comm "$_pid")
    _exe=$(safe_readlink "/proc/$_pid/exe")
    _base=""
    [ -n "$_exe" ] && _base=$(basename "$_exe" 2>/dev/null || printf '')

    # A process may disappear between reads; that is normal and not an error.
    [ -n "$_comm$_exe" ] || continue
    PROC_SCAN_COUNT=$((PROC_SCAN_COUNT + 1))

    if is_kaspersky_process "$_comm" "$_base" "$_exe"; then
        # Tabs/newlines are normalized so TSV remains parseable.
        _comm_s=$(printf '%s' "$_comm" | tr '\t\r\n' '   ')
        _exe_s=$(printf '%s' "$_exe" | tr '\t\r\n' '   ')
        printf '%s\037%s\037%s\n' "$_pid" "$_comm_s" "$_exe_s" >> "$KASP_FILE"
    fi

    if is_falco_process "$_comm" "$_base" "$_exe"; then
        resolve_falco_mode "$_pid"
        _comm_s=$(printf '%s' "$_comm" | tr '\t\r\n' '   ')
        _exe_s=$(printf '%s' "$_exe" | tr '\t\r\n' '   ')
        _cfg_s=$(printf '%s' "$FALCO_CFG_PATH" | tr '\t\r\n' '   ')
        _ev_s=$(printf '%s' "$FALCO_MODE_EVIDENCE" | tr '\t\r\n' '   ')
        printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
            "$_pid" "$_comm_s" "$_exe_s" "$FALCO_MODE" "$FALCO_MODE_CONFIDENCE" \
            "$_cfg_s" "$FALCO_BPF_FD_COUNT" "$_ev_s" >> "$FALCO_FILE"
    fi
done

KASP_COUNT=$(wc -l < "$KASP_FILE" 2>/dev/null | tr -d '[:space:]')
FALCO_COUNT=$(wc -l < "$FALCO_FILE" 2>/dev/null | tr -d '[:space:]')
[ -n "$KASP_COUNT" ] || KASP_COUNT=0
[ -n "$FALCO_COUNT" ] || FALCO_COUNT=0

# Derive a machine-level Falco summary without hiding multi-process/mixed-mode cases.
if [ "$FALCO_COUNT" -eq 0 ]; then
    FALCO_SUMMARY="not_running"
else
    _modes=$(awk -F "$US" '{print $4}' "$FALCO_FILE" | sort -u 2>/dev/null)
    _mc=$(printf '%s\n' "$_modes" | sed '/^$/d' | wc -l | tr -d '[:space:]')
    if [ "${_mc:-0}" -eq 1 ]; then
        FALCO_SUMMARY=$(printf '%s\n' "$_modes" | head -n 1)
    else
        FALCO_SUMMARY="mixed"
    fi
fi

printf '{\n'
printf '  "schema_version": 1,\n'
printf '  "tool_version": '; jstr "$TOOL_VERSION"; printf ',\n'
printf '  "hostname": '; jstr "$HOSTNAME_VAL"; printf ',\n'
printf '  "distro": {"id": '; jstr "$DISTRO_ID"; printf ', "version_id": '; jstr "$DISTRO_VERSION"; printf ', "pretty_name": '; jstr "$DISTRO_PRETTY"; printf ', "source": '; jstr "$DISTRO_SOURCE"; printf '},\n'
printf '  "kernel": {"release": '; jstr "$KERNEL_RELEASE"; printf ', "version": '; jstr "$KERNEL_VERSION"; printf ', "arch": '; jstr "$ARCH"; printf '},\n'
printf '  "secure_boot": {"state": '; jstr "$SECURE_BOOT"; printf ', "source": '; jstr "$SECURE_BOOT_SOURCE"; printf ', "detail": '; jstr "$SECURE_BOOT_DETAIL"; printf '},\n'
printf '  "proc_visibility": '; jstr "$PROC_VISIBILITY"; printf ',\n'
printf '  "kaspersky": {\n'
printf '    "running": %s,\n' "$( [ "$KASP_COUNT" -gt 0 ] && printf true || printf false )"
printf '    "process_count": %s,\n' "$KASP_COUNT"
printf '    "processes": ['
_first=1
while IFS="$US" read -r _pid _comm _exe; do
    [ -n "$_pid" ] || continue
    [ "$_first" -eq 1 ] || printf ','
    printf '\n      {"pid": %s, "comm": ' "$_pid"; jstr "$_comm"; printf ', "exe": '; jstr "$_exe"; printf '}'
    _first=0
done < "$KASP_FILE"
[ "$_first" -eq 1 ] || printf '\n    '
printf ']\n'
printf '  },\n'
printf '  "falco": {\n'
printf '    "running": %s,\n' "$( [ "$FALCO_COUNT" -gt 0 ] && printf true || printf false )"
printf '    "process_count": %s,\n' "$FALCO_COUNT"
printf '    "driver_summary": '; jstr "$FALCO_SUMMARY"; printf ',\n'
printf '    "kernel_module_loaded": %s,\n' "$FALCO_KMOD_LOADED"
printf '    "processes": ['
_first=1
while IFS="$US" read -r _pid _comm _exe _mode _conf _cfg _bpf_count _evidence; do
    [ -n "$_pid" ] || continue
    [ "$_first" -eq 1 ] || printf ','
    printf '\n      {"pid": %s, "comm": ' "$_pid"; jstr "$_comm"; printf ', "exe": '; jstr "$_exe"
    printf ', "driver_mode": '; jstr "$_mode"; printf ', "confidence": '; jstr "$_conf"
    printf ', "config": '; jstr "$_cfg"; printf ', "bpf_fd_count": %s, "evidence": ' "${_bpf_count:-0}"; jstr "$_evidence"; printf '}'
    _first=0
done < "$FALCO_FILE"
[ "$_first" -eq 1 ] || printf '\n    '
printf ']\n'
printf '  },\n'
printf '  "diagnostics": {"proc_entries_scanned": %s, "notes": [' "$PROC_SCAN_COUNT"
_note_first=1
if [ "$PROC_VISIBILITY" != "root" ] && [ "$PROC_VISIBILITY" != "normal_or_unknown" ]; then
    jstr "procfs hidepid may hide Kaspersky/Falco processes from an unprivileged user"
    _note_first=0
fi
if [ "$SECURE_BOOT_SOURCE" = "container_efi_not_visible" ]; then
    [ "$_note_first" -eq 1 ] || printf ', '
    jstr "Secure Boot must be collected on the host; this container cannot see host EFI state"
    _note_first=0
fi
if [ "$FALCO_COUNT" -gt 0 ]; then
    if awk -F "$US" '$4=="unknown" || $4=="ebpf_unknown" {found=1} END {exit !found}' "$FALCO_FILE" 2>/dev/null; then
        [ "$_note_first" -eq 1 ] || printf ', '
        jstr "run as root for stronger Falco FD/environment evidence when /proc permissions are restricted"
    fi
fi
printf ']}\n'
printf '}\n'

exit 0
