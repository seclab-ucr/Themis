@load base/protocols/conn
@load base/frameworks/netcontrol

const broker_port: port = 9999/tcp &redef;

event NetControl::init()
	{
	local netcontrol_acld = NetControl::create_acld([$acld_host=127.0.0.1, $acld_port=broker_port, $acld_topic="zeek/event/pacf"]);
	NetControl::activate(netcontrol_acld, 0);
	}

event NetControl::init_done()
	{
	print "NeControl is starting operations";
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added", endpoint$network;
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule added successfully", r$id, msg;
	}

event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule error", r$id, msg;
	}

event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	print "Rule timeout", r$id, i;
	}

event NetControl::rule_removed(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule removed", r$id, msg;
	}

event connection_established(c: connection)
	{
	local id = c$id;
	local flow = NetControl::Flow(
		$src_h=addr_to_subnet(id$orig_h),
		$dst_h=addr_to_subnet(id$resp_h)
	);
	local e: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=20sec];

	NetControl::add_rule(r);
	}

