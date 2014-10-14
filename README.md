Relayr API
============

Library for Python 2 and 3 to communicate with the Relayr API. 

Dependencies
------------
Relayr depends on the Python packages requests and pubnub. Make sure you have it installed using `pip install -r requirements.txt`

How to use
----------
Before using it, make sure you generate an oauth token using the following steps:

  * Go to [API KEYS section on the Relayr developer dashboard](https://developer.relayr.io/dashboard/apps/myApps).
  * Click on `New API key`
  * Fill in `title`, `description` and click `next`
  * It will ask you about a callback url, click `next`
  * It will show you your app ID, client ID and secret, click on `finalize`
  * A new box will be added to the page with your newly generated app, click on the button `Generate Token`
  * A new field called `token` will be added to the box: that is the string you need!

With your newly generated Oauth token in one hand, take your temperature sensor and turn it on. Open a python console and type the following commands.


    >> import relayr
    >> from __future__ import print_function
    >> api = relayr.API("YOUR OAUTH TOKEN")
    >> tempsens = [dev for dev in api.devices if 'Thermometer' in dev.name][0]
    >> chan = tempsens.get_channel()
    >> chan.add_message_handler(print)
    >> chan.start()


Now wait a few seconds for the channel to be connected and it should start printing the temperature and humidity! 

Too tired to type? From the command line type `python3 relayr.py YOUR_OAUTH_TOKEN`
