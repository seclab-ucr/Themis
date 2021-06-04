import logging
import re
import ipaddress
import datetime
import broker
import broker.zeek
from select import select
from enum import Enum, unique

logger = logging.getLogger(__name__)

def convertRecord(name, m):
    if not isinstance(m, tuple):
        logger.error("Got non record element")

    rec = m

    elements = None
    if name == "rule":
        elements = ['ty', 'target', 'entity', 'expire', 'priority', 'location', 'out_port', 'mod', 'id', 'cid']
    elif name == "rule->entity":
        elements = ['ty', 'conn', 'flow', 'ip', 'mac']
    elif name == "rule->entity->conn":
        elements = ['orig_h', 'orig_p', 'resp_h', 'resp_p']
    elif name == "rule->entity->flow":
        elements = ['src_h', 'src_p', 'dst_h', 'dst_p', 'src_m', 'dst_m']
    elif name == "rule->mod":
        elements = ['src_h', 'src_p', 'dst_h', 'dst_p', 'src_m', 'dst_m', 'redirect_port']
    else:
        logger.error("Unknown record type %s", name)
        return

    dict = {}
    for i in range(0, len(elements)):
        if rec[i] is None:
            dict[elements[i]] = None
            continue
        elif isinstance(rec[i], tuple):
            dict[elements[i]] = convertRecord(name+"->"+elements[i], rec[i])
            continue

        dict[elements[i]] = convertElement(rec[i])

    return dict

def convertElement(el):
    if isinstance(el, broker.Count):
        return el.value

    if isinstance(el, ipaddress.IPv4Address):
        return str(el);

    if isinstance(el, ipaddress.IPv6Address):
        return str(el);

    if isinstance(el, ipaddress.IPv4Network):
        return str(el);

    if isinstance(el, ipaddress.IPv6Network):
        return str(el);

    if isinstance(el, broker.Port):
        p = str(el)
        ex = re.compile('([0-9]+)(.*)')
        res = ex.match(p)
        return (res.group(1), res.group(2))

    if isinstance(el, broker.Enum):
        tmp = el.name
        return re.sub(r'.*::', r'', tmp)

    if isinstance(el, tuple):
        return tuple(convertElement(ell) for ell in el);

    if isinstance(el, datetime.datetime):
        return el

    if isinstance(el, datetime.timedelta):
        return el

    if isinstance(el, int):
        return el

    if isinstance(el, str):
        return el

    logger.error("Unsupported type %s", type(el) )
    return el;

@unique
class ResponseType(Enum):
    ConnectionEstablished = 1
    Error = 2
    AddRule = 3
    RemoveRule = 4
    SelfEvent = 5

class NetControlResponse:
    def __init__(self):
        self.type = (ResponseType.Error)
        self.errormsg = ""
        self.rule = ""

    def __init__(self, rty, **kwargs):
        self.type = rty
        self.errormsg = kwargs.get('errormsg', '')
        self.pluginid = kwargs.get('pluginid', None)
        self.rule = kwargs.get('rule', None)
        self.rawrule = kwargs.get('rawrule', None)

class Endpoint:
    def __init__(self, queue, host, port):
        self.queuename = queue
        self.epl = broker.Endpoint()
        self.epl.listen(host, port)
        self.status_subscriber = self.epl.make_status_subscriber(True)
        self.subscriber = self.epl.make_subscriber(self.queuename)

        logger.debug("Set up listener for "+host+":"+str(port)+" ("+queue+")")
    def getNextCommand(self):
        while True:
            logger.debug("Waiting for broker message...")
            readable, writable, exceptional = select(
                    [self.status_subscriber.fd(), self.subscriber.fd()],
                    [], [])

            if ( self.status_subscriber.fd() in readable ):
                logger.debug("Handling broker status message...")
                msg = self.status_subscriber.get()

                if isinstance(msg, broker.Status):
                    if msg.code() == broker.SC.PeerAdded:
                        logger.info("Incoming connection established")
                        return NetControlResponse(ResponseType.ConnectionEstablished)

                    continue

            elif ( self.subscriber.fd() in readable ):
                logger.debug("Handling broker message...")
                msg = self.subscriber.get()
                return self.handleBrokerMessage(msg)

    def handleBrokerMessage(self, m):
        if type(m).__name__ != "tuple":
            logger.error("Unexpected type %s, expected tuple", type(m).__name__)
            return NetControlResponse(ResponseType.Error)

        if len(m) < 1:
            logger.error("Tuple without content?")
            return NetControlResponse(ResponseType.Error)

        (topic, event) = m
        ev = broker.zeek.Event(event)

        event_name = ev.name()
        logger.debug("Got event "+event_name)

        if event_name == "NetControl::broker_add_rule":
            return self._add_remove_rule(ev.args(), ResponseType.AddRule)
        elif event_name == "NetControl::broker_remove_rule":
            return self._add_remove_rule(ev.args(), ResponseType.RemoveRule)
        elif event_name == "NetControl::broker_rule_added":
            return NetControlResponse(ResponseType.SelfEvent)
        elif event_name == "NetControl::broker_rule_removed":
            return NetControlResponse(ResponseType.SelfEvent)
        elif event_name == "NetControl::broker_rule_error":
            return NetControlResponse(ResponseType.SelfEvent)
        elif event_name == "NetControl::broker_rule_timeout":
            return NetControlResponse(ResponseType.SelfEvent)
        else:
            logger.warning("Unknown event %s", event_name)
            return NetControlResponse(ResponseType.Error, errormsg="Unknown event"+event_name)

    def _add_remove_rule(self, m, rtype):
        if  ( (rtype == ResponseType.AddRule) and ( len(m) != 2 ) ) or ( (rtype == ResponseType.RemoveRule) and ( len(m) != 3 ) ):
            logger.error("wrong number of elements or type in tuple for add/remove_rule event")
            return NetControlResponse(ResponseType.Error, errormsg="wrong number of elements or type in tuple for add/remove_rule event")

        if ( not isinstance(m[0], broker.Count) or
             not isinstance(m[1], tuple) ):
            logger.error("wrong types of elements or type in tuple for add/remove_rule event")
            return NetControlResponse(ResponseType.Error, errormsg="wrong types of elements or type in tuple for add/remove_rule event")

        id = m[0].value
        rule = convertRecord("rule", m[1])

        return NetControlResponse(rtype, pluginid=id, rule=rule, rawrule=m[1])

    def sendRuleAdded(self, response, msg):
        self._rule_event("added", response, msg)

    def sendRuleRemoved(self, response, msg):
        self._rule_event("removed", response, msg)

    def sendRuleError(self, response, msg):
        self._rule_event("error", response, msg)

    def _rule_event(self, event, response, msg):
        args = [broker.Count(response.pluginid), response.rawrule, msg]
        ev = broker.zeek.Event("NetControl::broker_rule_"+event, *args)
        self.epl.publish(self.queuename, ev)
