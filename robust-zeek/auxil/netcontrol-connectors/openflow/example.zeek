@load base/protocols/conn
@load base/frameworks/openflow
@load base/frameworks/netcontrol

const broker_port: port = 9999/tcp &redef;
global of_controller: OpenFlow::Controller;

# Switch datapath ID
const switch_dpid: count = 12 &redef;
# port on which Zeek is listening - we install a rule to the switch to mirror traffic here...
const switch_bro_port: count = 19 &redef;


event NetControl::init() &priority=2
	{
	of_controller = OpenFlow::broker_new("of", 127.0.0.1, broker_port, "bro/openflow", switch_dpid);
	local pacf_of = NetControl::create_openflow(of_controller, NetControl::OfConfig($monitor=T, $forward=F, $priority_offset=+5));
	NetControl::activate(pacf_of, 0);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added", endpoint$network;
	}

event NetControl::init_done()
	{
	print "NeControl is starting operations";
	OpenFlow::flow_clear(of_controller);
	OpenFlow::flow_mod(of_controller, [], [$cookie=OpenFlow::generate_cookie(1337), $priority=2, $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(switch_bro_port)]]);
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule added successfully", r$id;
	}

event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule error", r$id, msg;
	}

event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	print "Rule timeout", r$id, i;
	}

event OpenFlow::flow_mod_success(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	#print "Flow mod success";
	}

event OpenFlow::flow_mod_failure(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow mod failure", flow_mod$cookie, msg;
	}

event OpenFlow::flow_removed(name: string, match: OpenFlow::ofp_match, cookie: count, priority: count, reason: count, duration_sec: count, idle_timeout: count, packet_count: count, byte_count: count)
	{
	print "Flow removed", match;
	}

# Shunt all ssl, gridftp and ssh connections after we cannot get any data from them anymore

event ssl_established(c: connection)
	{
	local id = c$id;
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	}

event GridFTP::data_channel_detected(c: connection)
	{
	local id = c$id;
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	}

event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	if ( ! c$ssh$auth_success )
		return;

	local id = c$id;
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5sec);
	print current_time();
	}
