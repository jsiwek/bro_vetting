##! Sets up the vetting module to work in a cluster setting.  The whitelist
##! is maintained on the manager node.  Worker nodes delegate the checking
##! of whether a host is in the whitelist to the manager.

@load ./main

@load base/frameworks/cluster

redef Cluster::worker2manager_events += /^Vetting::check_host$/;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./read_whitelist
@load ./check
@endif

@load ./monitor
