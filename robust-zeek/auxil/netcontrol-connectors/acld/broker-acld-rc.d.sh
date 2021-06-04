#!/bin/sh
# @(#) $Id: broker-acld,v 1.8 2018/04/25 17:26:04 leres Exp $ (LBL)
#

# PROVIDE: broker-acld
# REQUIRE: LOGIN
# KEYWORD: shutdown
#
# Variables that can be set in /etc/rc.conf:
#
#    broker_acld_enable
#    broker_acld_asuser		user to run as
#    broker_acld_netcontrol	path to net-control directory
#    broker_acld_pidfile
#    broker_acld_hosts		one or more acld hosts
#    broker_acld_port		default acld port
#    broker_acld_logfile	path to logfile
#
# broker_acld_hosts hosts can override the default port, e.g. 127.0.0.1,1234
#

. /etc/rc.subr

name=broker_acld
rcvar=broker_acld_enable

load_rc_config "$name"

asuser=${broker_acld_asuser:-bro}
netcontrol=${broker_acld_netcontrol:-/home/bro/bro-netcontrol}
pidfile="${broker_acld_pidfile:-/var/run/broker-acld.pid}"

broker_acld_enable=${broker_acld_enable:-"NO"}
broker_acld_hosts=${broker_acld_hosts:-127.0.0.1}
broker_acld_port=${broker_acld_port:-1965}
broker_acld_logfile=${broker_acld_logfile:-${netcontrol}/acld/broker-logs}
broker_acld_env="PYTHONPATH=${netcontrol}/lib/python"

command=/usr/sbin/daemon
command_interpreter=python3
procname=${broker_acld_program:-${netcontrol}/acld/broker-acld.py}
unset broker_acld_program

command_args="-u ${asuser} -p ${pidfile} ${procname}"
for host in ${broker_acld_hosts}; do
	command_args="${command_args} --acld_host ${host}"
done
command_args="${command_args} --acld_port ${broker_acld_port}"
command_args="${command_args} --logfile ${broker_acld_logfile}"
command_args="${command_args} --rotate"
command_args="${command_args} ${broker_acld_flags}"

run_rc_command "$1"
