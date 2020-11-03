#!/usr/bin/python
#
# Copyright 2015 LRZ - Christoph Ostermeier

"""See docstring for UserAgentGenerator class"""


from autopkglib import Processor, ProcessorError
import uuid;

__all__ = ["UserAgentGenerator"]


class UserAgentGenerator(Processor):
    """Generates a random Useragent to for Fake purposes"""
    description = __doc__

    input_variables = {
    }
    output_variables = {
        "useragent": {
            "description": "the generated useragent",
        },
    }


    def main(self):
        fakestr=str(uuid.uuid4().get_hex().upper()[0:12])
        self.env['useragent'] = 'Mozilla 5/0 ' + fakestr



if __name__ == "__main__":
    PROCESSOR = UserAgentGenerator ()
    PROCESSOR.execute_shell()
