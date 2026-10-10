# Home Assistant App: Pluggie


## Installation

1. Click on button to add Pluggie repository to your Home Assistant:

   [![Open your Home Assistant instance and show the add app repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fpluggieio%2Fha-pluggie)

   ..or add the Pluggie repository manually (Settings -> Apps -> Install app -> ⋮ (top right) -> Repositories):
   ```
   https://github.com/pluggieio/ha-pluggie
   ```
2. Check for updates (⋮ menu, top right) and reload the Install app page
3. Choose the Pluggie app
4. Click on the INSTALL button


### One-Time Setup

1. On the Pluggie app page, turn on "Show in sidebar" and click START
2. Let Home Assistant trust Pluggie as a reverse proxy.

   **Home Assistant 2026.8 or newer:** go to Settings -> System -> Network -> HTTP server and set:
   - "Trust X-Forwarded-For": on
   - "Trusted proxies": `172.30.32.0/23`

   Save the settings. Home Assistant restarts; afterwards confirm the new settings, otherwise Home Assistant reverts them after 5 minutes.

   **Older versions:** add/update this in your `configuration.yaml` and restart Home Assistant:
   ```yaml
   http:
     use_x_forwarded_for: true
     trusted_proxies:
       - 172.30.32.0/23  # Pluggie app
   ```

   Upgrading to 2026.8 or newer imports an existing `http:` block automatically on first start. Afterwards remove the `http:` block from `configuration.yaml` (Home Assistant shows a repair; the YAML configuration stops working in 2027.2.0).

   Home Assistant sees the real client IP address, so login attempt notifications show the real client and you can also turn on "Enable IP banning" in the same HTTP server settings.

   Step-by-step guide with troubleshooting: https://pluggie.io/blog/home-assistant-trusted-proxies
3. Open Pluggie from the sidebar and set the "Access Key" and other settings
4. Check the app status in the Log tab
5. Test the connection by opening your browser and navigating to your chosen generated domain name:
   ```
   https://generated-domain-name.pluggie.net
   ```
   or your custom domain if configured in the admin interface (https://my.pluggie.net/)


## Configuration

### Required Configuration

```
Access Key: YOUR_ACCESS_KEY          # Access key from https://my.pluggie.net
```


### Advanced Configuration

```
Log Level: info                        # Optional: debug, info, warning, error; Default: info
Proxied Host: ""                       # Optional: Full URL of proxied host; Default: http://homeassistant.local.hass.io:8123

# Basic Auth
Basic Authentication Username: ""      # Optional: Username for Basic Auth protection
Basic Authentication Password: ""      # Optional: Password for Basic Auth protection

# Let's Encrypt Configuration
ACME Root CA Certificate: ""           # Optional: Custom root CA certificate
ACME Server: ""                        # Optional: Custom ACME server URL
Key Type: ecdsa                        # Optional: Certificate key type (ecdsa, rsa)
Elliptic Curve: secp256r1              # Optional: Curve for ECDSA keys (secp256r1, secp384r1); Default: secp256r1
```

### Configuration Options Explained

**Basic**
- `Access Key`: Your unique access key that identifies and authorizes your Home Assistant instance with Pluggie services.

**Logging**
- `Log Level`: Controls the detail level of logging. Use 'debug' for troubleshooting, 'info' for normal operation.

**Network**
- `Proxied Host`: URL of your Home Assistant (default) or web enabled device to connect to (e.g. https://myrouter.internal:8080). If Home Assistant listens on another port (new Home Assistant OS installations since 2026.8 use port 80), set e.g. `http://homeassistant.local.hass.io` (no port).

**Security**
- `Basic Authentication Username`: Optional username for Basic Auth protection. If set along with password, will enable Basic Auth.
- `Basic Authentication Password`: Optional password for Basic Auth protection. Must be set together with username.


**SSL/TLS Certificate**
- `ACME Root CA Certificate`: Custom certificate authority. Only needed if you use your own CA.
- `ACME Server`: Alternative ACME server URL. Use this if you want to use a different certificate provider.
- `Key Type`: Choose between ECDSA (faster, modern) or RSA (wider compatibility) certificates.
- `Elliptic Curve`: Security level for ECDSA certificates. secp256r1 is recommended for most users.


## Support

- Got questions? Visit our website at [https://pluggie.io](https://pluggie.io)
- Need help? Contact our support team through support@pluggie.net
