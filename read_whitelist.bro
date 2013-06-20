##! Reads a simple whitelist of IP addresses from a file on disk.
##! The format of the file is expected to be the string "host" on a line to
##! indicate the column name followed one IP address per line.

@load ./main
@load base/frameworks/input

module Vetting;

type Idx: record {
	host: addr;
};

event bro_init() &priority=5
	{
	Input::add_table([$source=host_whitelist_filename, $mode=Input::REREAD,
	                  $name=input_handle, $idx=Idx,
	                  $destination=host_whitelist]);
	}

# This event was renamed to Input::end_of_data after 2.1, it's only here for
# compatibility purposes.
event Input::update_finished(name: string, source: string) &priority=5
	{
	if ( name == input_handle )
		whitelist_ready = T;
	}

event Input::end_of_data(name: string, source: string) &priority=5
	{
	if ( name == input_handle )
		whitelist_ready = T;
	}
