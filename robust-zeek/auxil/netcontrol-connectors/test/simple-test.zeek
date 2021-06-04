@load base/frameworks/netcontrol

redef exit_only_after_terminate = T;

event NetControl::init()
	{
	local netcontrol_broker = NetControl::create_broker(NetControl::BrokerConfig($host=127.0.0.1, $bport=9977/tcp, $topic="zeek/event/netcontrol-example"), T);
	NetControl::activate(netcontrol_broker, 0);
	}

function test_mac_flow()
	{
	local flow = NetControl::Flow(
		$src_m = "FF:FF:FF:FF:FF:FF"
	);
	local e: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

function test_mac()
	{
	local e: NetControl::Entity = [$ty=NetControl::MAC, $mac="FF:FF:FF:FF:FF:FF"];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

event NetControl::init_done() &priority=-5
	{
	print "Init done";
	NetControl::shunt_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 30sec);
	NetControl::drop_address(1.1.2.2, 15sec, "Hi there");
	NetControl::whitelist_address(1.2.3.4, 15sec);
	NetControl::redirect_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 5, 30sec);
	NetControl::quarantine_host(127.0.0.2, 8.8.8.8, 127.0.0.3, 15sec);
	test_mac();
	test_mac_flow();
	}

