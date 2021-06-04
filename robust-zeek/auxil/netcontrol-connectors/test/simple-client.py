#!/usr/bin/env python3

# Simple command line client using the provided API. Test, e.g., with
# the provided simple-test.zeek

import logging, netcontrol, pprint

logging.basicConfig(level=logging.DEBUG)

ep = netcontrol.Endpoint("zeek/event/netcontrol-example", "127.0.0.1", 9977);
pp = pprint.PrettyPrinter(indent=4)

while 1==1:
    response = ep.getNextCommand()

    if response.type == netcontrol.ResponseType.AddRule:
        ep.sendRuleAdded(response, "")
    elif response.type == netcontrol.ResponseType.RemoveRule:
        ep.sendRuleRemoved(response, "")
    else:
        continue

    pp.pprint(response.rule)
