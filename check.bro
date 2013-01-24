##! Handles the checking of whether a host is within a whitelist and raises
##! a notice if it's not.

@load base/frameworks/notice

@load ./main

module Vetting;

event Vetting::re_check_host(host: addr, cid: conn_id, uid: string)
	{
	if ( ! Vetting::whitelist_ready )
		Reporter::fatal(fmt("Failed to ready vetted host whitelist from %s",
		                    Vetting::host_whitelist_filename));
	else
		event check_host(host, cid, uid);
	}

event Vetting::check_host(host: addr, cid: conn_id, uid: string) &priority=5
	{
	if ( ! Vetting::whitelist_ready )
		schedule 15sec { Vetting::re_check_host(host, cid, uid) };
	else if ( host !in Vetting::host_whitelist )
		{
		local msg = fmt("New host, %s, not in vetting whitelist %s",
		                host, Vetting::host_whitelist_filename);
		NOTICE([$note=Unvetted_Host, $msg=msg, $uid=uid, $id=cid,
		        $identifier=fmt("%s", host),
		        $suppress_for=Vetting::check_interval]);
		}
	}
