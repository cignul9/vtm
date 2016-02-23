## A python 3 module to facilitate using Brocade Virtual Traffic Manager's REST API
### (a product formerly known as Riverbed's Stingray or Steelapp)

#### Supported configuration entry types:
 - action_program
 - action
 - appliance
 - application_firewall
 - aptimizer
 - bandwidth
 - bgp_neighbor
 - cloud_api_credential
 - custom
 - dns_server
 - event_type
 - extra_file
 - glb_service
 - global_setting
 - kerberos
 - license_key
 - location
 - monitor_script
 - monitors
 - persistence
 - pool
 - protection
 - rate
 - rule_authenticator
 - rule
 - security
 - service_level_monitor
 - ssl
 - traffic_ip_group
 - user_authenticator
 - user_group
 - virtual_server

#### Installation
pip install vtm

#### Usage
##### Example 1:

```
from vtm import VtmConnection, VtmConfig
# Create a connection instance to your VTM
vconn = VtmConnection(
  'stingray.example.com',
  'my_automation_account',
  '178wtSVnD9BZggbiFFW5',
  to_console=False,
)
# Create a new blank default configuration of type 'pool' create an instance of 
# VtmConfig. Set to_console to false if you're writing a script and not 
# developing something interactively with python's shell.
new_pool_conf = VtmConfig(
  api_version=vconn.api_version,
  config_type='pool',
  to_console=False,
)
# The config data structure provided by VtmConfig gives you most of what you 
# need, but you must still set some data.  In the case of a pool config you 
# need to create a list of dicts for the nodes in the pool.  Print 
# new_pool_conf.help for info on the bare minimum changes necessary to apply the 
# config.
new_pool_conf.config['properties']['basic']['nodes_table'] = [
  {
    'node': '1.1.1.1:8080',
    'state': 'active',
    'weight': 1,
    'priority': 1,
  },
  {
    'node': '1.1.1.2:8080', 
    'state': 'disabled',
    'weight': 1,
    'priority': 1,
  },
]
# Apply the config, which creates a new pool or modifies an existing one 
# depending on whether or not the name you specify here was the already present
vconn.put_config(
  new_pool_conf.config_type
  ,'test_pool'
  ,new_pool_conf.config
)
```

##### Example 2:

```
from vtm import VtmConnection, VtmConfig
# Same as before. Create a connection instance to your VTM
vconn = VtmConnection(
  'stingray.example.com',
  'my_automation_account',
  '178wtSVnD9BZggbiFFW5',
  to_console=False,
)
# This time suppose we don't need to create anything new, we just want to 
# modify something already in place.  In that case there is no need to
# instantiate VtmConfig.  Get the data structures you need from the connection.
# Let's change the port on a virtual server
vs_config = vconn.get_config('virtual_server', 'test_service')
vs_config['properties']['basic']['port'] = 8080

# Now apply the changed config back to the VTM
vconn.put_config('virtual_server', 'test_service', vs_config)
```

##### Example 3:

```
vconn = VtmConnection(
  'stingray.example.com',
  'my_automation_account',
  '178wtSVnD9BZggbiFFW5',
  to_console=False,
)

# Delete a virtual server and it's major components.
vconn.delete_config('virtual_server', 'test_service')
vconn.delete_config('pool', 'test_pool')
vconn.delete_config('traffic_ip_group', 'test_tip')
```
