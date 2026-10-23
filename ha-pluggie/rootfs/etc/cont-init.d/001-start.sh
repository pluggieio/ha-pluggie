#!/usr/bin/with-contenv bashio

log_level=$(bashio::config 'log_level' 'info')
bashio::log.level "${log_level}"

# export for python scripts
export LOG_LEVEL=${log_level}

bashio::log.info "Starting Pluggie ${PLUGGIE_VERSION}.."

# Check if running on Home Assistant else its Docker
if [[ -n "${SUPERVISOR_TOKEN:-}" ]]; then
	bashio::log.info "For administration, please visit Pluggie in sidebar of your Home Assistant"
else
	bashio::log.info "For administration, please visit http://${PLUGGIE_HOST}:${PLUGGIE_PORT} in your browser"
fi

# clean environment
rm -f /etc/pluggie.state /tmp/restart_reason /tmp/pluggie_health /tmp/pluggie_cert_busy \
    /tmp/pluggie_dns_check /tmp/pluggie_mtls_poll /tmp/pluggie_commands_pull \
    /tmp/pluggie_commands_legacy /tmp/cert_verify_reported.json
