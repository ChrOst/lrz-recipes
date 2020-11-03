#!/usr/bin/python
#
# Copyright 2015 LRZ - Christoph Ostermeier

"""See docstring for VersionFix class"""


from autopkglib import Processor, ProcessorError

__all__ = ["VersionFix"]


class VersionFix(Processor):
    """Uses the pkginfo data from update provider to derive version."""
    description = ("descr")

    input_variables = {
        "version": {
            "required": True,
            "description": "full version.",
        }
    }
    output_variables = {
        "pkgversion": {
            "description": "full fixed pkg compatible version string.",
        }
    }


    def main(self):
        """Get version info"""
        version = self.env['version']
        version = version.replace('\n','')
        version = version.replace('-','')
        version = version.replace('.svn','')
        tmp = version.split(' ')
        version = tmp[0]
        self.env['version'] = version
        self.env['pkgversion'] = version


if __name__ == "__main__":
    PROCESSOR = VersionFix ()
    PROCESSOR.execute_shell()
