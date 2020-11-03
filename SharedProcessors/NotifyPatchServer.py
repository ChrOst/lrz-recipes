#!/usr/local/autopkg/python
#
# Copyright 2020 LRZ - Christoph Ostermeier
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Configuration:
# defaults write com.github.autopkg PATCH_URL https://the.url.to.your.patchServer:1234
# defaults write com.github.autopkg PATCH_TOKEN yourPatchServerTokenForEdits
# Usage:
# autopkg run Firefox.jss --key STOP_IF_NO_JSS_UPLOAD=False --post de.lrz.SharedProcessors/NotifyPatchServer
#
# STOP_IF_NO_JSS_UPLOAD is not necessary.
# But if you have multiple JSSImporter Processors running in one Recipe you'd have to do that.
#

"""See docstring for NotifyPatchServer class"""

import os
import plistlib
import requests
import shutil
import xml
import subprocess
import json
from datetime import datetime
from glob import glob

from autopkglib import ProcessorError
from autopkglib.FlatPkgUnpacker import FlatPkgUnpacker
from autopkglib.PkgPayloadUnpacker import PkgPayloadUnpacker

__all__ = ["NotifyPatchServer"]


class NotifyPatchServer(PkgPayloadUnpacker, FlatPkgUnpacker):
    """
    This is a Post-Processor for AutoPkg.
    It unpacks the newly generated Package, searches for an App-Bundle and extracts all Information needed for
    updating an Patchserver (https://github.com/brysontyrrell/PatchServer). The unpacked data will be removed from
    disk afterwards.
    """

    description = __doc__

    input_variables = {
    }

    output_variables = {
    }

    # Required for FlatPkgUnpacker
    source_path = None
    # Remove these directories after processing
    cleanupDirs = []

    def nps_genPatchVersion(self, app_path):
        """Generates a PatchVersion for Patchserver based on the current AppBundle"""
        # Extract the Filename and open the Info.plist
        filename = os.path.basename(app_path.rstrip("/"))
        info_plist_path = os.path.join(app_path, "Contents", "Info.plist")
        # Try to extract data to an hashtable
        try:
            info_plist = plistlib.readPlist(info_plist_path)
        except EnvironmentError as err:
            print('ERROR: {}'.format(err))
            raise SystemExit(1)
        except xml.parsers.expat.ExpatError:
            info_plist = self.read_binary_plist(info_plist_path)

        # Grab name (with spaces) and id (without spaces) + bundleId and Version from Info.plist
        name = filename.replace('.app', '')
        try:
            patch_id = info_plist["CFBundleName"].replace(' ', '')
        except KeyError:
            patch_id = name.replace(' ', '')
        bundle_id = info_plist["CFBundleIdentifier"]
        version = self.env["version"]

        # If a minimumOperatingSystem is set, use that
        try:
            min_os = info_plist["LSMinimumSystemVersion"]
        except KeyError:
            min_os = "10.9"

        # get timestamps
        timestamp = datetime.utcfromtimestamp(
            os.path.getmtime(app_path)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # generate patchData-Hashtable
        patch = {
            "version": version,
            "releaseDate": timestamp,
            "standalone": True,
            "minimumOperatingSystem": min_os,
            "reboot": False,
            "killApps": [{"bundleId": bundle_id, "appName": filename}],
            "components": [{"name": name, "version": version, "criteria": [
                    {"name": "Application Bundle ID", "operator": "is", "value": bundle_id, "type": "recon", "and": True},
                    {"name": "Application Version", "operator": "is", "value": version, "type": "recon"}
                ]}
            ],
            "capabilities": [{"name": "Operating System Version", "operator": "greater than or equal", "value": min_os, "type": "recon"}],
            "dependencies": []
        }

        return patch_id, patch

    def nps_notifyServer(self, id, patchData):
        """Sends the new PatchVersion to a PatchServer"""
        session = requests.Session()
        # Generate headers
        headers = {}
        if self.env.get("PATCH_TOKEN"):
            headers.update({"Authorization": "Bearer {}".format(self.env.get("PATCH_TOKEN"))})
        # Build url for the Patchtitle
        patchUrl = "%s/api/v1/title/%s/version" % (self.env["PATCH_URL"], id)

        # Fire Request
        response = session.request(
            method = "POST",
            url = patchUrl,
            headers = headers,
            json = patchData
        )
        # Get errors if any
        try:
            response.raise_for_status()
        except requests.HTTPError:
            if response.status_code == 409:
                self.output("%s was already at this version" % id)
            else:
                raise ProcessorError("Error %s sending Patch-Data for %s" % (str(response.status_code),id))

    def nps_unpack(self):
        """Unpacks the Package file using other Processors"""
        # Emulate FlatPkgUnpacker/main-method
        self.env["destination_path"] = os.path.join(self.env["RECIPE_CACHE_DIR"], "UnpackedPackage")
        self.cleanupDirs.append(self.env["destination_path"])
        self.output("Unpacking '%s' to '%s'" % (self.env["pkg_path"], self.env["destination_path"]))
        self.source_path = self.env["pkg_path"]
        self.unpack_flat_pkg()
        # Emulate PkgPayloadUnpacker/main-method
        self.env["pkg_payload_path"] = os.path.join(self.env["destination_path"], "Payload")
        # If there is a payload already, unpack it
        if os.path.isfile(self.env["pkg_payload_path"]):
            matches, app_glob_path = self.nps_find_app()
        else:
            # Sometimes there is no Payload, so we have to find the .pkg which contains it.
            pkgs = os.path.join(self.env["destination_path"], "*.pkg", "Payload")
            payloadmatches = glob(pkgs)
            if len(payloadmatches) == 0:
                ProcessorError("No Subpackage found by globbing %s" % pkgs)
            else:
                for payloadmatch in payloadmatches:
                    self.env["pkg_payload_path"] = payloadmatch
                    matches, app_glob_path = self.nps_find_app()
                    if len(matches) > 0:
                        break
        if len(matches) == 0:
            ProcessorError("No match found by globbing %s" % app_glob_path)
        elif len(matches) > 1:
            ProcessorError("Multiple matches found by globbing %s" % app_glob_path)
        else:
            self.output("Found %s" % matches[0])
            return matches[0]

    def nps_find_app(self):
        """Helper Function to unpack Payloads"""
        self.env["destination_path"] = os.path.join(self.env["RECIPE_CACHE_DIR"], "UnpackedPayload")
        self.cleanupDirs.append(self.env["destination_path"])
        self.output("Unpacking Payload to'%s'" % self.env["destination_path"])
        self.unpack_pkg_payload()
        # Find Application in unpacked Payload and return the Path
        # Try it in Apps Folder
        app_glob_path = os.path.join(self.env["destination_path"], "Applications", "*.app")
        matches = glob(app_glob_path)
        if len(matches) > 0:
            return matches, app_glob_path
        else:
            # Afterwards try it directly, fixes it for Virtualbox.
            app_glob_path = os.path.join(self.env["destination_path"], "*.app")
            return glob(app_glob_path), app_glob_path

    def read_binary_plist(self, plist_path):
        process = subprocess.Popen(
            ['plutil', '-convert', 'json', '-o', '-', plist_path],
            stdout=subprocess.PIPE
        )
        response = process.communicate()
        try:
            return json.loads(response[0])
        except ValueError:
            print('ERROR: Unable to read the application plist!')
            raise SystemExit(1)

    def cleanup(self):
        """Directory cleanup"""
        for directory in self.cleanupDirs:
            if os.path.isdir(directory):
                shutil.rmtree(directory)

    def main(self):
        app_path = self.nps_unpack()
        patch_id, patch = self.nps_genPatchVersion(app_path)
        self.nps_notifyServer(patch_id, patch)
        self.cleanup()


if __name__ == "__main__":
    PROCESSOR = NotifyPatchServer()
    PROCESSOR.execute_shell()
