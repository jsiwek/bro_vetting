##! A script for detecting new hosts within some set of subnets for which
##! hosts are supposed to be manually vetted and whitelisted.  The whitelist
##! of already-vetted IPs is populated at startup from a file on disk, but
##! is re-read automatically at run-time if modified. Any traffic from an IP
##! within one of the subnets, but not in the whitelist raises a notice.

@load base/frameworks/notice

module Vetting;

export {
	redef enum Notice::Type += {
		## Raised when seeing traffic from a host in :bro:see:`Vetting::subnets`
		## but not in :bro:see:`Vetting::host_whitelist`.
		Unvetted_Host
	};

	## The set of subnets that are supposed to be vetted.
	const subnets: set[subnet] &redef;

	## The name of the file on disk which contains a list of IP addresses
	## that are already vetted.  Read at startup and upon modification.
	const host_whitelist_filename: string &redef;

	## Descriptive handle to associate with the *name* field of
	## :bro:see:`Input::TableDescription`.
	const input_handle: string = "vetted-host-whitelist" &redef;

	## Interval for which activity of a host previously reported via
	## :bro:see:`Vetting::check_host` can be ignored.  i.e. the event will be
	## raised at most once per this interval of time.
	const check_interval: interval = 1day &redef;

	## Set of IPs that are vetted.  Populated from
	## :bro:see:`Vetting::host_whitelist_filename`.
	global host_whitelist: set[addr];

	## Whether the input framework has finished reading
	## :bro:see:`Vetting::host_whitelist_filename`.
	global whitelist_ready: bool = F;

	## Raised when activity for a host in :bro:see:`Vetting::subnets` can be
	## checked against :bro:see:`Vetting::host_whitelist`.
	global check_host: event(host: addr);
}
