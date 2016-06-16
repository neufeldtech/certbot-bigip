"""Let's Encrypt F5 BIG-IP plugin."""
import sys

import certbot_bigip

sys.modules['letsencrypt_bigip'] = certbot_bigip
