##! Periodically monitors for new activity of hosts within a subnet range and
##! raises an event to check whether they're whitelisted.

@load ./main

module Vetting;

global checked_hosts: set[addr] &create_expire=Vetting::check_interval;

function do_check(host: addr, c: connection)
	{
	if ( host !in Vetting::subnets ) return;
	if ( host in Vetting::checked_hosts ) return;

	add checked_hosts[host];
	event Vetting::check_host(host, c$id, c$uid);
	}

# Both sides are known to be active if a TCP handshake completed, so check them.
event connection_established(c: connection) &priority=5
	{
	if ( c$orig$state != TCP_ESTABLISHED ) return;
	if ( c$resp$state != TCP_ESTABLISHED ) return;

	do_check(c$id$orig_h, c);
	do_check(c$id$resp_h, c);
	}

# For non-TCP, have to wait until timeout to check endpoint if it had activity.
event connection_state_remove(c: connection) &priority=5
	{
	if ( c$orig$size != 0 )
		do_check(c$id$orig_h, c);
	if ( c$resp$size != 0 )
		do_check(c$id$resp_h, c);
	}
