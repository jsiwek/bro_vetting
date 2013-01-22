##! Periodically monitors for new activity of hosts within a subnet range and
##! raises an event to check whether they're whitelisted.

@load ./main

module Vetting;

global checked_hosts: set[addr] &create_expire=Vetting::check_interval;

event new_connection(c: connection) &priority=5
	{
	for ( host in set(c$id$orig_h, c$id$resp_h) )
		{
		if ( host in Vetting::checked_hosts ) next;

		if ( host !in Vetting::subnets ) next;

		add checked_hosts[host];
		event Vetting::check_host(host);
		}
	}
