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


## Client certificates (mTLS)

Optional extra protection for your Pluggie address: only devices with a client certificate issued by this app can open it. Settings are in the Pluggie panel under **Show Advanced Settings → Client Certificates (mTLS)** and take effect immediately (no Save needed).

**Modes**
- `Off`: client certificates are not requested (default).
- `Test`: certificates are requested, accepted and recorded ("Last seen"), nothing is blocked. Use it to check that your devices work.
- `Enforce`: requests without a valid certificate are rejected with an explanation page. Available only after at least one device has connected with its certificate in Test mode.

**Adding a device**
1. Enter a device name and click **Add device**. A `.p12` certificate file is downloaded and its password is shown once; it is not stored anywhere.
2. Install the file on the device:
   - Android (requires a screen lock — PIN, pattern or password — before it lets you install a certificate):
     1. Download the `.p12` file to the phone.
     2. Open Settings, search for "certificate", tap "Install a certificate" → "VPN & app user certificate", pick the file and enter the password shown when the certificate was issued (fallback: Security & privacy → More security settings → Encryption & credentials).
     3. Choose the certificate when Chrome or the Home Assistant app asks for it.
   - Home Assistant companion app on iOS (2026.9.1 or newer): the app asks for the certificate when the server requests it.
   - Desktop: import the file into the system keychain or your browser.
3. Open your Pluggie address on the device and check that "Last seen" is filled in, then switch to Enforce.

One certificate per device; **Revoke** blocks that device only. Certificates are valid for 5 years.

**Changed your Pluggie address?** No restart needed: usually within a minute the Pluggie app reconnects, gets a certificate for the new address and keeps the mode and device certificates. Device certificates stay valid, nothing has to be reissued. Update the address in the Home Assistant companion app and in your bookmarks; the browser or app may ask once more which certificate to use for the new address. The certificate authority keeps the previous address in its name; that is expected.

**Locked out?** The Pluggie panel in the Home Assistant sidebar and your local network are never affected. Open the panel and switch the mode to Off.

**Locked out while away?** You can also turn client certificates off from your Pluggie account at [my.pluggie.net](https://my.pluggie.net); this requires two-factor authentication on the account. The Pluggie endpoint announces such a request through the tunnel, so the app switches the mode to Off within seconds and shows a notice in the Pluggie panel; if the app is offline, the request is applied when it connects again (within 7 days).

**Backup:** the certificate authority (including its private key) is stored in the app's private `/data` folder and never leaves your Home Assistant.
- It is in a Home Assistant backup only when the backup includes the Pluggie app; include it in your automatic backups.
- Uninstalling the app, or reinstalling it from a different repository URL, deletes it (the access key and the Let's Encrypt certificate are kept). Client certificates are then off and the Pluggie panel shows a notice: restore a backup or set up client certificates again.
- After restoring an older backup, revoke again every device certificate you revoked after that backup was made.
- "Delete all certificates" removes the authority together with all device certificates.


## Account recovery

If you lose access to your Pluggie account (password and two-factor authentication), contact Pluggie support. Support gives you a one-time code. Open the Pluggie panel → **Show Advanced Settings → Account Recovery**, enter the code and click **Verify**. The app proves to Pluggie that it holds this tunnel's access key, and you get a link that lets you set a new password and turns off two-factor authentication on your account. The link is shown only once and is not stored or logged by the app. The code is valid for a limited time and can be used once; after 5 attempts within 15 minutes you have to wait.


## Support

- Got questions? Visit our website at [https://pluggie.io](https://pluggie.io)
- Need help? Contact our support team through support@pluggie.net
