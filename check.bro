##! Handles the checking of whether a host is within a whitelist and raises
##! a notice if it's not.

@load base/frameworks/notice

@load ./main

module Vetting;

event Vetting::re_check_host(host: addr)
	{
	if ( ! Vetting::whitelist_ready )
		Reporter::fatal(fmt("Failed to ready vetted host whitelist from %s",
		                    Vetting::host_whitelist_filename));
	else
		event check_host(host);
	}

event Vetting::check_host(host: addr) &priority=5
	{
	if ( ! Vetting::whitelist_ready )
		schedule 15sec { Vetting::re_check_host(host) };
	else if ( host !in Vetting::host_whitelist )
		{
		local msg = fmt("New host, %s, not in vetting whitelist %s",
						host, Vetting::host_whitelist_filename);
		NOTICE([$note=Unvetted_Host, $msg=msg, $identifer=fmt("%s", host)]);
		}
	}
