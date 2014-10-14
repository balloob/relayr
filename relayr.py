"""
Python binding to the Relayr-api.
"""
from __future__ import print_function
import json
import requests
import logging
import Pubnub
import threading
import time

BASE_URL = "https://api.relayr.io/"


class RelayrException(Exception):
    """ Base exception for Relayr related errors. """
    pass


class Unauthorized(RelayrException):
    """ Raised when API-call was unauthorized. """
    pass


# pylint: disable=too-many-instance-attributes
class API(object):
    """ Allows to interface with the Relayr-api. """

    def __init__(self, oauth_token):
        self.oauth_token = oauth_token
        self.headers = {"User-Agent": "relary.py",
                        "Authorization": "Bearer {}".format(oauth_token),
                        "Content-Type": "application/json"}
        self.logger = logging.getLogger(__name__ + ".API")

        self.user_info = None
        self._devices = None
        self._transmitters = None

        # Get user id and validate Oauth token in the process
        self.app_info = self.get_app_info()
        self.user_info = self.get_user_info()

        self.pubclient = None

    @property
    def app_id(self):
        """ app id related to the oauth token. """
        return self.app_info['id']

    @property
    def user_id(self):
        """ User id related to the oauth token. """
        return self.user_info['id']

    @property
    def devices(self):
        """ List of devices of the user this oauth token has access too. """
        if self._devices is None:
            try:
                self._devices = self.get_devices()
            except Unauthorized:
                self._devices = []

        return self._devices

    @property
    def transmitters(self):
        """ List of devices of the user this oauth token has access too. """
        if self._transmitters is None:
            try:
                self._transmitters = self.get_transmitters()
            except Unauthorized:
                self._transmitters = []

        return self._transmitters

    def get_user_info(self):
        """ Retrieve current user information. """
        return self.api_request('get', "oauth2/user-info")

    def get_app_info(self):
        """ Returns current app info. """
        return self.api_request('get', "oauth2/app-info")

    def get_devices(self):
        """ Retrieve devices. """
        return [Device.from_dict(self, data) for data in
                self.api_request(
                    'get', "users/{}/devices".format(self.user_id))]

    def get_transmitters(self):
        """ Retrieve transmitters. """
        return self.api_request(
            'get', "users/{}/transmitters".format(self.user_id))

    def open_channel(self, device):
        """ Subscribes app to device readings. """
        return Channel.from_dict(
            self, device,
            self.api_request(
                'post', "apps/{}/devices/{}".format(
                    self.app_id, device.device_id)))

    def _connect_channel(self, channel):
        """ Connects a channel to pubnub. """
        self._init_pubnub(channel)

        self.pubclient.subscribe(
            channel.channel,
            callback=channel.pubnub_callback,
            error=channel.pubnub_callback,
            connect=channel.pubnub_connect,
            reconnect=channel.pubnub_reconnect,
            disconnect=channel.pubnub_disconnect)

        return channel

    def _close_channel(self, channel):
        """ Closes a channel at relayr side. """
        self.pubclient.unsubscribe(channel.channel)

        self.api_request(
            'delete', "apps/{}/devices/{}".format(
                self.app_id, channel.device.device_id))

    def api_request(self, method, path, data=None):
        """ Make a request to the relayr-api. """
        self.logger.debug("API:{} - {} - {}".format(method, path, data))

        req = requests.request(
            method, BASE_URL + path, data=data, headers=self.headers)

        if req.status_code == 401:
            raise Unauthorized(req.json()['message'])

        return None if req.status_code == 204 else req.json()

    def _init_pubnub(self, channel):
        """ The first channel we get has data for us to initialize
            a pubnub client. """
        if self.pubclient is None:
            self.pubclient = Pubnub.Pubnub(
                publish_key=channel.subscribe_key,
                subscribe_key=channel.subscribe_key,
                cipher_key=channel.cipher_key,
                auth_key=channel.auth_key)


class Device(object):
    """ Represents a Relayr device. """

    # pylint: disable=too-many-arguments, too-many-instance-attributes
    def __init__(self, api, firmware_version, device_id, model, name, owner,
                 public, secret):
        self._api = api
        self.firmware_version = firmware_version
        self.device_id = device_id
        self.model = model
        self.name = name
        self.owner = owner
        self.public = public
        self.secret = secret

    def get_configuration(self):
        """ Returns device configuration. """
        return self._api.api_request(
            'get', 'devices/{}/firmware'.format(self.device_id))

    def get_channel(self):
        """ Subscribe current app to this device. """
        return self._api.open_channel(self)

    def send_command(self, command, optional_suffix=""):
        """ Send a command to the device. """
        return self._api.api_request(
            'post', 'devices/{}/cmd/{}'.format(
                self.device_id, optional_suffix),
            data=json.dumps({"cmd": command}))

    def __repr__(self):
        return "<Device {}>".format(self.name)

    @staticmethod
    def from_dict(api, data):
        """ Creates Device objects from dicts retrieved from the API. """
        return Device(
            api,
            data.get("firmwareVersion"),
            data.get("id"),
            data.get("model"),
            data.get("name"),
            data.get("owner"),
            data.get("public"),
            data.get("secret"),
            )


class Channel(threading.Thread):
    """ Represents a channel between app and device. """

    # pylint: disable=too-many-arguments
    def __init__(self, api, device, auth_key, channel, cipher_key,
                 subscribe_key):
        super(Channel, self).__init__()

        self._api = api
        self.logger = logging.getLogger(__name__ + ".Channel")
        self._stop_event = threading.Event()

        self.device = device
        self.auth_key = auth_key
        self.channel = channel
        self.cipher_key = cipher_key
        self.subscribe_key = subscribe_key

        self.daemon = True

        self._handlers = []

    def add_message_handler(self, handler):
        """ Add your message handlers here.
            They should accept Device, dict. """
        self._handlers.append(handler)

    # pylint: disable=unused-argument
    def pubnub_callback(self, message, channel):
        """ pubnub callback for when message received. """
        try:
            message = message.strip()
            data = json.loads(message)

            for callback in self._handlers:
                callback(self.device, data)

        except ValueError:
            self.logger.exception(
                "Quiting because error parsing json: {}".format(message))

            self.stop()

    def pubnub_error(self, message):
        """ pubnub callback for when error happening. """
        self.logger.debug("error called: {}".format(message.strip()))

    def pubnub_connect(self, message):
        """ pubnub callback for when connected. """
        self.logger.debug("connect called: {}".format(message.strip()))

    def pubnub_reconnect(self, message):
        """ pubnub callback for when reconnected. """
        self.logger.debug("reconnect called: {}".format(message.strip()))

    def pubnub_disconnect(self, message):
        """ pubnub callback for when disconnected. """
        self.logger.debug("disconnect called: {}".format(message.strip()))

    def run(self):
        """ Start listening to the channel. """
        # pylint: disable=protected-access
        self._api._connect_channel(self)

        while not self._stop_event.is_set():
            time.sleep(1)

    def stop(self):
        """ Stop listening to the channel. """
        self._stop_event.set()

        # pylint: disable=protected-access
        self._api._close_channel(self)

    @staticmethod
    def from_dict(api, device, data):
        """ Creates channel object from dict retrieved from the API. """
        return Channel(
            api,
            device,
            data.get("authKey"),
            data.get("channel"),
            data.get("cipherKey"),
            data.get("subscribeKey")
            )


if __name__ == "__main__":
    from pprint import pprint
    import sys

    if len(sys.argv) != 2:
        print("For testing, call python relayr.py <OAUTH_TOKEN>")
        sys.exit()

    logging.basicConfig(level=logging.DEBUG)

    print("Initializing API")
    # pylint: disable=invalid-name
    rel = API(sys.argv[1])
    print()

    def test_method(desc, method):
        """ Helper method to test an API method. """
        print(desc)

        try:
            pprint(method())
        except Unauthorized as ex:
            print(ex)

        print()

    test_method("app info", rel.get_app_info)
    test_method("user info", rel.get_user_info)
    test_method("transmitters", rel.get_transmitters)
    test_method("devices", rel.get_devices)

    tempsens = [dev for dev in rel.devices if 'Thermometer' in dev.name][0]
    chan = tempsens.get_channel()

    def print_callback(device, data):
        """ Example callback method that prints data. """
        print(device, data)
        print()

    chan.add_message_handler(print_callback)

    chan.start()

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            chan.stop()
            break
