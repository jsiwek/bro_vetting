##! A utility script that can check for stale entries in a host whitelist
##! based on activity of hosts in a vetting_hosts.log file.  Writes results
##! to file stale_whitelist.txt.

@load base/frameworks/input
@load frameworks/communication/listen

redef Communication::listen_port = 13131/tcp;

module CollectStaleWhitelist;

export {
	## Path to a vetting_hosts.log.
	const activity_log_filename: string &redef;

	## Path to a host whitelist.
	const whitelist_filename: string &redef;
}

# All vetted hosts in whitelist.
global vetted_hosts: set[addr];

# Only the hosts in the "activity" log.
global active_hosts: set[time, addr];

type VettedHostsIdx: record {
	host: addr;
};

type ActiveHostsIdx: record {
	ts:   time;
	host: addr;
};

event bro_init()
	{
	Input::add_table([$source=activity_log_filename,
	                  $name="vetted_host_activity", $idx=ActiveHostsIdx,
	                  $destination=active_hosts]);
	Input::add_table([$source=whitelist_filename,
	                  $name="vetted_host_whitelist", $idx=VettedHostsIdx,
	                  $destination=vetted_hosts]);
	}

global eod_count = 0;

event Input::end_of_data(name: string, source: string)
	{
	++eod_count;
	if ( eod_count == 2 )
		{
		local stale_hosts = vetted_hosts;

		for ( [t, h] in active_hosts )
			delete stale_hosts[h];

		local f = open("stale_whitelist.txt");
		print f, "host";
		for ( h in stale_hosts )
			print f, h;
		close(f);

		terminate();
		}
	}
