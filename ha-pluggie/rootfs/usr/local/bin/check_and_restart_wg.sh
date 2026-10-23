#!/usr/bin/with-contenv bashio

# Function to check DNS records
check_dns() {
    local hostname=$1
    local dns_server=$2

    if [ -z "$hostname" ] || [ "$hostname" = "." ]; then
        bashio::log.debug "Empty hostname provided, skipping DNS check"
        return 0
    fi

    # Reject inputs containing shell metacharacters before passing to dig.
    # Defense in depth against a compromised API response or hand-edited
    # pluggie.json. DNS server accepts IPv4 and IPv6 literals.
    if ! [[ "$hostname" =~ ^[A-Za-z0-9.-]+$ ]] || [ ${#hostname} -gt 253 ]; then
        bashio::log.warning "Invalid hostname, skipping DNS check"
        return 0
    fi
    if ! [[ "$dns_server" =~ ^[0-9A-Fa-f.:]+$ ]]; then
        bashio::log.warning "Invalid DNS server, skipping DNS check"
        return 0
    fi

    bashio::log.debug "Checking ${hostname} using DNS ${dns_server}.." >&2
    local ip
    # Short timeouts: without internet the loop must not hang on retries
    ip=$(dig +short +time=3 +tries=2 "${hostname}" A "@${dns_server}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || echo "")
    bashio::log.debug "IP for ${hostname} from ${dns_server}: ${ip}" >&2
    echo "$ip"
}

# Function to restart WireGuard
restart_wireguard() {
    health_reset_baseline
    bashio::log.debug "Stopping WireGuard interface.."
    # Capture output from wg-quick down
    if wg-quick down "${PLUGGIE_INTERFACE1}" 2>&1 | while IFS= read -r line; do
        if [[ $line == \[#\]* ]]; then
            command="${line#*\] }"
            bashio::log.debug "WireGuard command: ${command}"
        else
            bashio::log.debug "WireGuard: ${line}"
        fi
    done; then
        bashio::log.debug "WireGuard interface stopped successfully."
    else
        bashio::log.warning "Failed to stop WireGuard interface. It may not have been running. Continuing.."
    fi

    bashio::log.debug "Starting WireGuard interface.."
    # Capture output from wg-quick up
    if wg-quick up "${PLUGGIE_INTERFACE1}" 2>&1 | while IFS= read -r line; do
        if [[ $line == \[#\]* ]]; then
            command="${line#*\] }"
            bashio::log.debug "WireGuard command: ${command}"
        else
            bashio::log.debug "WireGuard: ${line}"
        fi
    done; then
        bashio::log.debug "WireGuard interface started successfully."
        return 0
    else
        bashio::log.error "Failed to start WireGuard interface."
        return 1
    fi
}

CONFIG_REFRESH_TRIGGER="/tmp/pluggie_config_refresh"
CONFIG_CHECK_INTERVAL=900
COMMANDS_PULL_REQUEST="/tmp/pluggie_commands_pull"

# DNS is checked every DNS_CHECK_INTERVAL, after a failed tunnel health
# check at once and then every DNS_RETRY_INTERVAL while it keeps failing
# (the endpoint IP may have changed)
DNS_CHECK_STAMP="/tmp/pluggie_dns_check"
DNS_CHECK_INTERVAL=900
DNS_RETRY_INTERVAL=120

dns_check_due() {
    local last now interval=${DNS_CHECK_INTERVAL}
    [ "${vpn_restart_needed}" = true ] && return 0
    if [ -f "${HEALTH_STATE}" ] && [ "$(cut -d' ' -f2 "${HEALTH_STATE}")" != "0" ]; then
        interval=${DNS_RETRY_INTERVAL}
    fi
    last=$(stat -c %Y "${DNS_CHECK_STAMP}" 2>/dev/null || echo 0)
    now=$(date +%s)
    [ $(( now - last )) -ge "${interval}" ] || [ "${now}" -lt "${last}" ]
}

# Compare tunnel settings with the apiserver (GET, throttled); a change
# requests a refresh via CONFIG_REFRESH_TRIGGER. Result in config_check_rc.
check_remote_config() {
    config_check_rc=0
    /usr/local/bin/get_config.py --check --min-interval "${CONFIG_CHECK_INTERVAL}" || config_check_rc=$?
}

HEALTH_STATE="/tmp/pluggie_health"
HEALTH_MAX_FAILS=2
HEALTH_HANDSHAKE_MAX_AGE=180
# With keepalive the session is renewed about every 2 minutes; a handshake
# this recent proves the endpoint still has this peer, no ping needed
HEALTH_HANDSHAKE_FRESH=170
HEALTH_PING_ATTEMPTS=3
# Reconnect attempts while the endpoint stays unreachable; WireGuard itself
# recovers within seconds once packets flow again (roaming, keepalive)
HEALTH_BACKOFF=(60 120 240 480 900)

# Load health state: rx baseline, consecutive failures, health restarts, next allowed restart
health_load() {
    h_rx="-"
    h_fails=0
    h_restarts=0
    h_next=0
    if [ -f "${HEALTH_STATE}" ]; then
        read -r h_rx h_fails h_restarts h_next < "${HEALTH_STATE}" || true
    fi
    h_rx=${h_rx:--}
    h_fails=${h_fails:-0}
    h_restarts=${h_restarts:-0}
    h_next=${h_next:-0}
}

health_save() {
    echo "${h_rx} ${h_fails} ${h_restarts} ${h_next}" > "${HEALTH_STATE}"
}

# Drop rx baseline and failure count after WireGuard (re)start
health_reset_baseline() {
    health_load
    h_rx="-"
    h_fails=0
    health_save
}

# Bytes received from the edge peer
wg_rx_bytes() {
    wg show "${PLUGGIE_INTERFACE1}" transfer 2>/dev/null | awk 'NR==1 {print $2}' || true
}

# Seconds since the last completed handshake, empty if none
wg_handshake_age() {
    local ts
    ts=$(wg show "${PLUGGIE_INTERFACE1}" latest-handshakes 2>/dev/null | awk 'NR==1 {print $2}' || true)
    if [ -n "${ts}" ] && [ "${ts}" -gt 0 ]; then
        echo $(( $(date +%s) - ts ))
    fi
}

# Schedule the earliest next health-triggered restart
health_record_restart() {
    local idx
    health_load
    idx=${h_restarts}
    if [ "${idx}" -ge "${#HEALTH_BACKOFF[@]}" ]; then
        idx=$(( ${#HEALTH_BACKOFF[@]} - 1 ))
    fi
    h_next=$(( $(date +%s) + HEALTH_BACKOFF[idx] ))
    h_restarts=$(( h_restarts + 1 ))
    health_save
}

# Tunnel health: 0 healthy, 1 unhealthy, 2 restart due
check_tunnel_health() {
    local rx rx_after age i replies=0 now
    health_load
    rx=$(wg_rx_bytes)
    age=$(wg_handshake_age)

    # First check after start or counter reset: store baseline only
    if [ -n "${rx}" ] && { [ "${h_rx}" = "-" ] || [ "${rx}" -lt "${h_rx}" ]; }; then
        h_rx=${rx}
        h_fails=0
        health_save
        return 0
    fi

    # Data received from the edge within a valid session
    if [ -n "${rx}" ] && [ "${rx}" -gt "${h_rx}" ] && [ -n "${age}" ] && [ "${age}" -lt "${HEALTH_HANDSHAKE_MAX_AGE}" ]; then
        h_rx=${rx}
        h_fails=0
        h_restarts=0
        h_next=0
        health_save
        return 0
    fi

    if [ -n "${age}" ] && [ "${age}" -le "${HEALTH_HANDSHAKE_FRESH}" ]; then
        h_rx=${rx:-${h_rx}}
        h_fails=0
        h_restarts=0
        h_next=0
        health_save
        return 0
    fi

    # Probe the edge, stop at the first reply that also increased rx
    for i in $(seq 1 "${HEALTH_PING_ATTEMPTS}"); do
        if ping -q -c 1 -W 2 "${PLUGGIE_ENDPOINT1_IP_INT}" >/dev/null 2>&1; then
            replies=$(( replies + 1 ))
            rx_after=$(wg_rx_bytes)
            if [ -n "${rx}" ] && [ -n "${rx_after}" ] && [ "${rx_after}" -gt "${rx}" ]; then
                h_rx=${rx_after}
                h_fails=0
                h_restarts=0
                h_next=0
                health_save
                return 0
            fi
        fi
    done

    rx_after=$(wg_rx_bytes)
    h_rx=${rx_after:-${h_rx}}
    h_fails=$(( h_fails + 1 ))
    bashio::log.warning "Tunnel health check failed (${h_fails}x in a row, restart after ${HEALTH_MAX_FAILS}): no data from Pluggie endpoint, handshake age ${age:-n/a}${age:+s}, ${replies}/${HEALTH_PING_ATTEMPTS} ping replies"

    if [ "${h_fails}" -lt "${HEALTH_MAX_FAILS}" ]; then
        health_save
        return 1
    fi

    now=$(date +%s)
    if [ "${now}" -lt "${h_next}" ]; then
        bashio::log.warning "Tunnel restart postponed by backoff for $(( h_next - now ))s"
        health_save
        return 1
    fi

    health_save
    return 2
}

# Function to check certificate expiry and trigger renewal if needed.
# Rate-limited to one attempt per 12 hours via /tmp/last_cert_renew_attempt
# to avoid hammering ACME during outages or in tight loops.
check_cert_renewal() {
    local user_agent
    user_agent=$(bashio::config 'user_agent')
    local pluggie_dir
    if [[ "${user_agent}" == *"Pluggie-Client-HA"* ]]; then
        pluggie_dir=/ssl/pluggie
    else
        pluggie_dir=/data
    fi

    local cert_path="${pluggie_dir}/letsencrypt/live/${PLUGGIE_HOSTNAME}/fullchain.pem"
    local renew_threshold_seconds=$((30 * 86400))
    local rate_limit_file="/tmp/last_cert_renew_attempt"
    local rate_limit_seconds=$((12 * 3600))

    if [ ! -f "${cert_path}" ]; then
        bashio::log.debug "No certificate at ${cert_path}, skipping renewal check."
        return 0
    fi

    if openssl x509 -in "${cert_path}" -noout -checkend "${renew_threshold_seconds}" >/dev/null 2>&1; then
        bashio::log.debug "Certificate is valid for more than 30 days, no renewal needed."
        return 0
    fi

    # Cert is within renewal window. Apply rate limit.
    if [ -f "${rate_limit_file}" ]; then
        local last_attempt
        last_attempt=$(cat "${rate_limit_file}" 2>/dev/null || echo 0)
        local now
        now=$(date +%s)
        local elapsed=$((now - last_attempt))
        if [ "${elapsed}" -lt "${rate_limit_seconds}" ]; then
            bashio::log.debug "Cert renewal attempted ${elapsed}s ago, waiting for rate limit (${rate_limit_seconds}s)."
            return 0
        fi
    fi

    bashio::log.debug "Certificate expires within 30 days. Triggering renewal."
    date +%s > "${rate_limit_file}"

    # letsencrypt/run handles ACME failure gracefully (keeps existing cert) and
    # reloads nginx on success.
    /etc/services.d/letsencrypt/run
}

log_level=$(bashio::config 'log_level' 'info')
bashio::log.level "${log_level}"
export LOG_LEVEL=$(bashio::config 'log_level' 'info')

access_key=$(bashio::config 'configuration.access_key')
if [ "${access_key}" = "XXXXX" ] || [ -z "${access_key}" ]; then
    bashio::log.warning "No valid Access Key configured. WireGuard check will not run."
    exit 0
fi

# Read configuration from /data/pluggie.json
PLUGGIE_ENDPOINT1_SHORT=$(bashio::config 'pluggie_config.endpoint1_short')
PLUGGIE_ENDPOINT1_IP=$(bashio::config 'pluggie_config.endpoint1_ip')
PLUGGIE_ENDPOINT1_IP_INT=$(bashio::config 'pluggie_config.endpoint1_ip_int')
PLUGGIE_INTERFACE1=$(bashio::config 'pluggie_config.interface1')
PLUGGIE_APISERVER=$(bashio::config 'pluggie_config.apiserver')
PLUGGIE_HOSTNAME=$(bashio::config 'pluggie_config.hostname')
PLUGGIE_DNS=$(bashio::config 'pluggie_config.dns')

# Initialise variables
HOSTNAME_IP=""
CURRENT_ENDPOINT_IP=""

vpn_restart_needed=false

# Check if we dont have some variables empty
if [ -z "$PLUGGIE_HOSTNAME" ] || [ -z "$PLUGGIE_ENDPOINT1_SHORT" ] || [ -z "$PLUGGIE_ENDPOINT1_IP_INT" ]; then
    bashio::log.debug "Attempting to get configuration from API server..."
    if /usr/local/bin/get_config.py; then
        # Read configuration from just refreshed /data/pluggie.json
        PLUGGIE_ENDPOINT1_SHORT=$(bashio::config 'pluggie_config.endpoint1_short')
        PLUGGIE_ENDPOINT1_IP=$(bashio::config 'pluggie_config.endpoint1_ip')
        PLUGGIE_ENDPOINT1_IP_INT=$(bashio::config 'pluggie_config.endpoint1_ip_int')
        PLUGGIE_INTERFACE1=$(bashio::config 'pluggie_config.interface1')
        PLUGGIE_APISERVER=$(bashio::config 'pluggie_config.apiserver')
        PLUGGIE_HOSTNAME=$(bashio::config 'pluggie_config.hostname')
        PLUGGIE_DNS=$(bashio::config 'pluggie_config.dns')

        bashio::log.debug "Configuration obtained successfully. Restarting services..."
        cat /dev/null > "/etc/pluggie.state"
        vpn_restart_needed=true
    else
        ret=$?
        # Dont exit if there are connection issues
        if [ -f "/etc/pluggie.state" ] && [ "$(cat /etc/pluggie.state)" = "connectivity_issue" ]; then
            bashio::log.warning "Connectivity issues detected, keeping existing configuration and services running."
            vpn_restart_needed=false
            exit 0
        else
            bashio::log.error "Failed to get configuration from API server."
            exit 1
        fi
    fi
fi

if dns_check_due; then
    touch "${DNS_CHECK_STAMP}"

    # List of DNS servers to try (Cloudflare, Google, Quad9)
    dns_servers=("1.1.1.1" "8.8.8.8" "9.9.9.9")

    # Try DNS servers in order
    for server in "${dns_servers[@]}"; do
        # Check hostname IP
        HOSTNAME_IP=$(check_dns "${PLUGGIE_HOSTNAME}" "$server")
        if [ -n "${HOSTNAME_IP}" ]; then
            bashio::log.debug "Valid hostname IP found: ${HOSTNAME_IP}"

            # Check endpoint IP
            CURRENT_ENDPOINT_IP=$(check_dns "${PLUGGIE_ENDPOINT1_SHORT}" "$server")
            if [ -n "${CURRENT_ENDPOINT_IP}" ]; then
                bashio::log.debug "Valid Pluggie endpoint IP found: ${CURRENT_ENDPOINT_IP}"
                break
            fi
        fi
    done

    # If all DNS checks failed
    if [ -z "${HOSTNAME_IP}" ]; then
        bashio::log.error "Error resolving hostname ${PLUGGIE_HOSTNAME}. No valid IPs found."
        check_remote_config
        # 'sleep 60' instead of 'exit 1' to keep running for case the DNS records will become valid again
        bashio::log.info "Sleeping for 60 seconds to run loop again"
        sleep 60
        # exit 1
    fi

    if [ -z "${CURRENT_ENDPOINT_IP}" ]; then
        bashio::log.error "Error resolving Pluggie endpoints. No valid IPs found. Keeping WireGuard up with old DNS records."
        # 'sleep 60' instead of 'exit 1' to keep running for case the DNS records will become valid again
        bashio::log.info "Sleeping for 60 seconds to run loop again"
        sleep 60
        # exit 1
    fi
fi

bashio::log.debug "HOSTNAME_IP: ${HOSTNAME_IP}" >&2
bashio::log.debug "CURRENT_ENDPOINT_IP: ${CURRENT_ENDPOINT_IP}" >&2
bashio::log.debug "PLUGGIE_ENDPOINT1_IP: ${PLUGGIE_ENDPOINT1_IP}" >&2
bashio::log.debug "PLUGGIE_INTERFACE1: ${PLUGGIE_INTERFACE1}" >&2

# Hostname not pointing to the endpoint: hostname or endpoint changed in the
# Pluggie account (refresh below) or a DNS problem (keep running)
if [ -n "${HOSTNAME_IP}" ] && [ -n "${CURRENT_ENDPOINT_IP}" ] && [ "${HOSTNAME_IP}" != "${CURRENT_ENDPOINT_IP}" ]; then
    check_remote_config
    case "${config_check_rc}" in
        0) bashio::log.warning "Hostname ${PLUGGIE_HOSTNAME} resolves to ${HOSTNAME_IP}, not to the Pluggie endpoint (${CURRENT_ENDPOINT_IP}). Please check DNS." ;;
        3) ;;
        *) bashio::log.debug "Hostname IP (${HOSTNAME_IP}) does not match endpoint IP (${CURRENT_ENDPOINT_IP})" ;;
    esac
fi

# Refresh requested by get_config.py --check, cert_verify.py or mtls_remote.py
if [ -f "${CONFIG_REFRESH_TRIGGER}" ]; then
    rm -f "${CONFIG_REFRESH_TRIGGER}"
    vpn_restart_needed=true
fi

# Check if endpoint IP changed
if [ -n "${CURRENT_ENDPOINT_IP}" ] && [ -n "${PLUGGIE_ENDPOINT1_IP}" ] && [ "${CURRENT_ENDPOINT_IP}" != "${PLUGGIE_ENDPOINT1_IP}" ]; then
    bashio::log.warning "Pluggie endpoint IP address changed."
    vpn_restart_needed=true

    # Get config from API to check if apiserver also changed (migration scenario:
    # operator moved tunnel to a new edge and reassigned the apiserver).
    # Header piped via stdin so the bearer token doesn't appear in process args.
    response=$(printf 'Authorization: Bearer %s\n' "$(bashio::config 'configuration.access_key')" \
        | curl -s --header @- "https://${PLUGGIE_APISERVER}/api/settings")
    NEW_APISERVER=$(echo "${response}" | jq -r '.client_tunnel_settings.apiserver')

    # If API server changed, update it in config
    if [ -n "${NEW_APISERVER}" ] && [ "${NEW_APISERVER}" != "${PLUGGIE_APISERVER}" ] && [ "${NEW_APISERVER}" != "null" ]; then
        bashio::log.warning "API server changed from ${PLUGGIE_APISERVER} to ${NEW_APISERVER}"

        # Refresh /data/pluggie.json with jq
        temp_file=$(mktemp)
        jq --arg apiserver "${NEW_APISERVER}" \
           '.pluggie_config.apiserver = $apiserver' /data/pluggie.json > "$temp_file" && mv "$temp_file" /data/pluggie.json
    fi
fi

# Check VPN connectivity
health_rc=0
health_restart=false
if [ "${vpn_restart_needed}" = "false" ] && [ -n "${PLUGGIE_ENDPOINT1_IP_INT}" ]; then
    if check_tunnel_health; then
        health_rc=0
    else
        health_rc=$?
    fi
    if [ "${health_rc}" -eq 2 ]; then
        bashio::log.warning "Pluggie endpoint (${PLUGGIE_ENDPOINT1_IP_INT}) is not responding."
        vpn_restart_needed=true
        health_restart=true
    fi
fi

if [ "${vpn_restart_needed}" = true ]; then
    # Check config file
    if [ ! -f "/etc/wireguard/${PLUGGIE_INTERFACE1}.conf" ]; then
        bashio::log.warning "WireGuard configuration file does not exist. Skipping restart."
        exit 0
    fi

    if [ "${health_restart}" = true ]; then
        health_record_restart
    fi

    bashio::log.warning "Refreshing Pluggie configuration from API server.."
    if /usr/local/bin/get_config.py; then

        # Check if Pluggie endpoint was unreachable (API rolled back, config unchanged)
        if [ -f "/etc/pluggie.state" ] && [ "$(cat /etc/pluggie.state)" = "endpoint_unreachable" ]; then
            bashio::log.warning "Pluggie endpoint unreachable. Keeping existing WireGuard configuration, will retry next cycle."
            exit 0
        fi

        bashio::log.debug "Pluggie configuration refreshed."

        bashio::log.warning "Restarting WireGuard interface ${PLUGGIE_INTERFACE1}.."
        if restart_wireguard; then
            bashio::log.debug "Successfully restarted WireGuard interface ${PLUGGIE_INTERFACE1}."
            if [ -n "${CURRENT_ENDPOINT_IP}" ] && [ -n "${PLUGGIE_ENDPOINT1_IP}" ] && [ "${CURRENT_ENDPOINT_IP}" != "${PLUGGIE_ENDPOINT1_IP}" ]; then
                temp_file=$(mktemp)
                jq --arg ip "${CURRENT_ENDPOINT_IP}" \
                   '.pluggie_config.endpoint1_ip = $ip' /data/pluggie.json > "$temp_file" && mv "$temp_file" /data/pluggie.json
                bashio::log.debug "Updated endpoint1_ip in pluggie.json"
            fi

            # Restart nginx and refresh letsencrypt after wireguard
            nginx -s stop
            /etc/services.d/letsencrypt/run
        else
            bashio::log.error "Failed to restart WireGuard interface ${PLUGGIE_INTERFACE1}. Please check your WireGuard configuration."
            exit 1
        fi
    else
        ret=$?
        if [ $ret -eq 10 ]; then
            bashio::log.warning "Tunnel is disabled, skipping WireGuard and nginx operations"
            # Stop WireGuard if it's running
            if wg show "${PLUGGIE_INTERFACE1}" >/dev/null 2>&1; then
                bashio::log.warning "Stopping disabled WireGuard interface.."
                wg-quick down "${PLUGGIE_INTERFACE1}" 2>/dev/null
                bashio::log.debug "WireGuard interface stopped."
            fi
        else
            bashio::log.error "Failed to refresh Pluggie configuration"
        fi
    fi
elif [ "${health_rc}" -eq 0 ]; then
    bashio::log.debug "VPN connection is healthy. No need to restart WireGuard."
    # Update state to enabled if it was connectivity_issue (recovered from outage)
    if [ -f "/etc/pluggie.state" ] && [ "$(cat /etc/pluggie.state)" = "connectivity_issue" ]; then
        bashio::log.info "Connectivity restored, updating state to enabled."
        echo "enabled" > "/etc/pluggie.state"
        touch /tmp/cert_verify_trigger
        [ -f "${COMMANDS_PULL_REQUEST}" ] || echo 0 > "${COMMANDS_PULL_REQUEST}"
    fi
fi

# Periodic certificate renewal check
check_cert_renewal
