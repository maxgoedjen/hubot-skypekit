# Hubot SkypeKit Adapter

## Description

This adapter lets Hubot talk on Skype using [SkypeKit](https://dev.skype.com/skypekit).

## Configuring the Adapter

You need to download the [SkypeKit SDK](https://dev.skype.com/skypekit) and obtain a SkypeKit certificate. Make sure the runtime is running when Hubot is, and set the `HUBOT_SKYPEKIT_KEY_PATH` environment variable to the absolute path to the certificate.

The SkypeKit adapter requires only the following environment variables.

* `HUBOT_SKYPEKIT_USERNAME`
* `HUBOT_SKYPEKIT_PASSWORD`
* `HUBOT_SKYPEKIT_KEY_PATH`
    
## Acknowledgements

The coffeescript part of this project is heavily based off of [netpro2k's Skype adapter](https://github.com/netpro2k/hubot-skype)
