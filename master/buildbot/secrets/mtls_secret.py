# This file is part of Buildbot.  Buildbot is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Buildbot Team Members
"""
vault based providers
"""


from twisted.internet import defer

from buildbot import config
from buildbot.secrets.providers.base import SecretProviderBase
import requests
import json

class MtlsSecretServiceProvider(SecretProviderBase):
    """
    This class is used for custom MTLS secret providers.
    Current code handle the case for dicts and nested dicts and flattens them out to secrets dict
    It currently does not include the scenarios where Lists in a dict is to be considered. However it can be incorporated by changing the recurse_keys function definition... 
    """

    name = 'SecretInRequest'

    def checkConfig(self, vaultServer=None, vaultToken=None,cert=None,verify=None,headers=None):
        if not isinstance(vaultServer, str):
            config.error("vaultServer must be a string while it is {}".format(type(vaultServer)))
        if not isinstance(vaultToken, str):
            config.error("vaultToken must be a string while it is {}".format(type(vaultToken)))
        if not isinstance(headers,dict):
            config.error("vaultToken must be a dict while it is {}".format(type(headers)))

    def reconfigService(self, vaultServer=None, vaultToken=None,cert=None,verify=None,headers=None):
        self.secrets={}
        response = requests.post(vaultServer, data=vaultToken,cert=cert,verify=verify, headers=headers)
        if response.text:
        	self.recurse_keys(json.loads(response.text))
        return self.secrets

    def recurse_keys(self,nested_dict):
        for key in nested_dict.keys():
            if isinstance(nested_dict[key],dict):
                self.recurse_keys(nested_dict[key])
            else:
                self.secrets[key]=nested_dict[key]

    def get(self, entry):
        """
        get the value from vault secret backend
        """

        # note that the HTTP path contains v1 for both versions of the key-value
        # secret engine. Different versions of the key-value engine are
        # effectively separate secret engines in vault, with the same base HTTP
        # API, but with different paths within it.
	
        return self.secrets.get(entry)
