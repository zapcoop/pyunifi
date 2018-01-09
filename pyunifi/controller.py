import json
import logging
import requests
import shutil
import time
import warnings


"""For testing purposes:
logging.basicConfig(filename='pyunifi.log', level=logging.WARN,
                    format='%(asctime)s %(message)s')
"""
log = logging.getLogger(__name__)


class APIError(Exception):
    pass


def retry_login(func, *args, **kwargs):
    """To reattempt login if requests exception(s) occur at time of call"""
    def wrapper(*args, **kwargs):
        try:
            try:
                return func(*args, **kwargs)
            except (requests.exceptions.RequestException,
                    APIError) as err:
                log.warning("Failed to perform %s due to %s" % (func, err))
                controller = args[0]
                controller._login()
                return func(*args, **kwargs)
        except Exception as err:
            raise APIError(err)
    return wrapper


class Controller(object):

    """Interact with a UniFi controller.

    Uses the JSON interface on port 8443 (HTTPS) to communicate with a UniFi
    controller. Operations will raise unifi.controller.APIError on obvious
    problems (such as login failure), but many errors (such as disconnecting a
    nonexistant client) will go unreported.

    >>> from unifi.controller import Controller
    >>> c = Controller('192.168.1.99', 'admin', 'p4ssw0rd')
    >>> for ap in c.get_aps():
    ...     print 'AP named %s with MAC %s' % (ap.get('name'), ap['mac'])
    ...
    AP named Study with MAC dc:9f:db:1a:59:07
    AP named Living Room with MAC dc:9f:db:1a:59:08
    AP named Garage with MAC dc:9f:db:1a:59:0b

    """

    def __init__(self, host, username, password, port=8443,
                 version='v5', site_id='default', ssl_verify=True):
        """
        :param host: the address of the controller host; IP or name
        :param username: the username to log in with
        :param password: the password to log in with
        :param port: the port of the controller host
        :param version: the base version of the controller API [v4|v5]
        :param site_id: the site ID to connect to
        :param ssl_verify: Verify the controllers SSL certificate, can also be "path/to/custom_cert.pem"
        """
        if float(version[1:]) < 4:
            raise APIError("%s controllers no longer supported" % version)

        self.host = host
        self.port = port
        self.version = version
        self.username = username
        self.password = password
        self.site_id = site_id
        self.url = 'https://' + host + ':' + str(port) + '/'
        self.api_url = self.url + 'api/s/' + site_id + '/'

        self.ssl_verify = ssl_verify

        if ssl_verify is False:
            warnings.simplefilter("ignore", category=requests.packages.
                                  urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()
        self.session.verify = ssl_verify

        log.debug('Controller for %s', self.url)
        self._login()

    @staticmethod
    def _jsondec(data):
        obj = json.loads(data)
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        else:
            return obj

    @retry_login
    def _read(self, url, params=None):
        # Try block to handle the unifi server being offline.
        r = self.session.get(url, params=params)
        return self._jsondec(r.text)

    def _api_read(self, url, params=None):
        return self._read(self.api_url + url, params)

    @retry_login
    def _write(self, url, params=None):
        r = self.session.post(url, json=params)
        return self._jsondec(r.text)

    def _api_write(self, url, params=None):
        return self._write(self.api_url + url, params)

    def _login(self):
        log.debug('login() as %s', self.username)

        # XXX Why doesn't passing in the dict work?
        params = str({'username': self.username, 'password': self.password})
        login_url = self.url + 'api/login'
        
        r = self.session.post(login_url, params)
        if r.status_code is not 200:
            raise APIError("Login failed - status code: %i" % r.status_code)

    def _logout(self):
        log.debug('logout()')
        self._api_write('logout')

    def get_alerts(self):
        """Return a list of all Alerts."""
        return self._api_write('stat/alarm')

    def get_alerts_unarchived(self):
        """Return a list of Alerts unarchived."""
        return self._api_write('stat/alarm', params={'archived': False})

    def get_statistics_last_24h(self):
        """Returns statistical data of the last 24h"""
        return self.get_statistics_24h(time())

    def get_statistics_24h(self, endtime):
        """Return statistical data last 24h from time"""

        params = {
            'attrs': ["bytes", "num_sta", "time"],
            'start': int(endtime - 86400) * 1000,
            'end': int(endtime - 3600) * 1000}
        return self._write(self.api_url + 'stat/report/hourly.site', params)

    def get_events(self):
        """Return a list of all Events."""
        return self._api_read('stat/event')

    def get_aps(self):
        """Return a list of all APs,
        with significant information about each.
        """
        # Set test to 0 instead of NULL
        params = {'_depth': 2, 'test': 0}
        return self._api_read('stat/device', params)

    def get_client(self, mac):
        """Get details about a specific client"""

        # stat/user/<mac> works better than stat/sta/<mac>
        # stat/sta seems to be only active clients
        # stat/user includes known but offline clients
        return self._api_read('stat/user/' + mac)[0]

    def get_clients(self):
        """Return a list of all active clients,
        with significant information about each.
        """
        return self._api_read('stat/sta')

    def get_users(self):
        """Return a list of all known clients,
        with significant information about each.
        """
        return self._api_read('list/user')

    def get_user_groups(self):
        """Return a list of user groups with its rate limiting settings."""
        return self._api_read('list/usergroup')

    def get_sysinfo(self):
        """Return basic system informations."""
        return self._api_read('stat/sysinfo')

    def get_sites(self):
        """Return a list of all sites,
        with their UID and description"""
        return self._read(self.url + 'api/self/sites')

    def get_wlan_conf(self):
        """Return a list of configured WLANs
        with their configuration parameters.
        """
        return self._api_read('list/wlanconf')

    def _run_command(self, command, params={}, mgr='stamgr'):
        log.debug('_run_command(%s)', command)
        params.update({'cmd': command})
        return self._write(self.api_url + 'cmd/' + mgr, params=params)

    def _mac_cmd(self, target_mac, command, mgr='stamgr'):
        log.debug('_mac_cmd(%s, %s)', target_mac, command)
        params = {'mac': target_mac}
        return self._run_command(command, params, mgr)

    def block_client(self, mac):
        """Add a client to the block list.

        :param mac: the MAC address of the client to block.
        """
        return self._mac_cmd(mac, 'block-sta')

    def unblock_client(self, mac):
        """Remove a client from the block list.

        :param mac: the MAC address of the client to unblock.
        """
        return self._mac_cmd(mac, 'unblock-sta')

    def disconnect_client(self, mac):
        """Disconnect a client.

        Disconnects a client, forcing them to reassociate. Useful when the
        connection is of bad quality to force a rescan.

        :param mac: the MAC address of the client to disconnect.
        """
        return self._mac_cmd(mac, 'kick-sta')

    def restart_ap(self, mac):
        """Restart an access point (by MAC).

        :param mac: the MAC address of the AP to restart.
        """
        return self._mac_cmd(mac, 'restart', 'devmgr')

    def restart_ap_name(self, name):
        """Restart an access point (by name).

        :param name: the name address of the AP to restart.
        """
        if not name:
            raise APIError('%s is not a valid name' % str(name))
        for ap in self.get_aps():
            if ap.get('state', 0) == 1 and ap.get('name', None) == name:
                return self.restart_ap(ap['mac'])

    def archive_all_alerts(self):
        """Archive all Alerts"""
        return self._run_command('archive-all-alarms', mgr='evtmgr')

    def create_backup(self):
        """Ask controller to create a backup archive file

        ..warning:
            This process puts significant load on the controller
            and may render it partially unresponsive for other requests.

        :return: URL path to backup file
        """
        res = self._run_command('backup', mgr='system')
        return res[0]['url']

    def get_backup(self, download_path=None, target_file='unifi-backup.unf'):
        """
        :param download_path: path to backup; if None is given one will be created
        :param target_file: Filename or full path to download the backup archive to,
                            should have .unf extension for restore.
        """
        if not download_path:
            download_path = self.create_backup()

        r = self.session.get(self.url + download_path, stream=True)
        with open(target_file, 'wb') as _backfh:
            return shutil.copyfileobj(r.raw, _backfh)

    def authorize_guest(self, guest_mac, minutes, up_bandwidth=None,
                        down_bandwidth=None, byte_quota=None, ap_mac=None):
        """
        Authorize a guest based on his MAC address.

        :param guest_mac: the guest MAC address: 'aa:bb:cc:dd:ee:ff'
        :param minutes: duration of the authorization in minutes
        :param up_bandwidth: up speed allowed in kbps
        :param down_bandwidth: down speed allowed in kbps
        :param byte_quota: quantity of bytes allowed in MB
        :param ap_mac: access point MAC address
        """
        cmd = 'authorize-guest'
        params = {'mac': guest_mac, 'minutes': minutes}

        if up_bandwidth:
            params['up'] = up_bandwidth
        if down_bandwidth:
            params['down'] = down_bandwidth
        if byte_quota:
            params['bytes'] = byte_quota
        if ap_mac:
            params['ap_mac'] = ap_mac
        return self._run_command(cmd, params=params)

    def unauthorize_guest(self, guest_mac):
        """
        Unauthorize a guest based on his MAC address.

        :param guest_mac: the guest MAC address: 'aa:bb:cc:dd:ee:ff'
        """
        cmd = 'unauthorize-guest'
        params = {'mac': guest_mac}
        return self._run_command(cmd, params=params)

    def get_firmware(self, cached=True, available=True, known=False, site=False):
        """
        Return a list of available/cached firmware versions

        :param cached: Return cached firmwares
        :param available: Return available (and not cached) firmwares
        :param known: Return only firmwares for known devices
        :param site: Return only firmwares for on-site devices
        :return: List of firmware dicts
        """
        res = []
        if cached:
            res.extend(self._run_command('list-cached', mgr='firmware'))
        if available:
            res.extend(self._run_command('list-available', mgr='firmware'))

        if known:
            res = [fw for fw in res if fw['knownDevice']]
        if site:
            res = [fw for fw in res if fw['siteDevice']]
        return res

    def cache_firmware(self, version, device):
        """
        Cache the firmware on the UniFi Controller

        .. warning:: Caching one device might very well cache others, as they're on shared platforms

        :param version: version to cache
        :param device: device model to cache (e.g. BZ2)
        :return: True/False
        """
        return self._run_command(
            'download', mgr='firmware',
            params={'device': device, 'version': version})[0]['result']

    def remove_firmware(self, version, device):
        """
        Remove cached firmware from the UniFi Controller

        .. warning:: Removing one device's firmware might very well remove others, as they're on shared platforms

        :param version: version to cache
        :param device: device model to cache (e.g. BZ2)
        :return: True/false
        """
        return self._run_command(
            'remove', mgr='firmware',
            params={'device': device, 'version': version})[0]['result']

    def get_tag(self):
        """Get all tags and their member MACs"""
        return self._api_read('rest/tag')
