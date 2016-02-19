#!/usr/bin/env python
import requests
import json
import sys
import warnings
from pprint import PrettyPrinter
import re

# Interacting with an instance of Virtual Traffic Manager (Stingray) is 
# facilitated by this class
class VtmConnection:
  def __init__(
    self,
    host,
    user,
    password,
    protocol = 'https',
    port = 9070,
    verify_ssl = False,
    to_console = True,
  ):
    self.user = user
    self.__password = password
    self.host = host
    self.protocol = protocol
    self.port = port
    self.__session = requests.Session()
    self.__auth = (self.user, self.__password)
    self.toConsole = to_console
    if self.toConsole:
      self.__pp = PrettyPrinter(indent=2)
    self.__activeConfigUrlSuffix = 'config/active/'
    self.__typeSuffixes = [
      {
        'name' : 'actionProgram',
        'urlSuffix' : 'action_programs/',
      },
      {
        'name' : 'action',
        'urlSuffix' : 'actions/',
      },
      {
        'name' : 'appliance',
        'urlSuffix' : 'appliance/',
      },
      {
        'name' : 'applicationFirewall',
        'urlSuffix' : 'application_firewall/',
      },
      {
        'name' : 'aptimizer',
        'urlSuffix' : 'aptimizer/',
      },
      {
        'name' : 'bandwidth',
        'urlSuffix' : 'bandwidth/',
      },
      {
        'name' : 'bgpNeighbor',
        'urlSuffix' : 'bgpneighbors/',
      },
      {
        'name' : 'cloudApiCredential',
        'urlSuffix' : 'cloud_api_credentials/',
      },
      {
        'name' : 'custom',
        'urlSuffix' : 'custom/',
      },
      {
        'name' : 'dnsServer',
        'urlSuffix' : 'dns_server/',
      },
      {
        'name' : 'eventType',
        'urlSuffix' : 'event_types/',
      },
      {
        'name' : 'extraFile',
        'urlSuffix' : 'extra_files/',
      },
      {
        'name' : 'glbService',
        'urlSuffix' : 'glb_services/'
      },
      {
        'name' : 'globalSetting',
        'urlSuffix' : 'global_settings/',
      },
      {
        'name' : 'kerberos',
        'urlSuffix' : 'kerberos/',
      },
      {
        'name' : 'licenseKey',
        'urlSuffix' : 'license_keys/',
      },
      {
        'name' : 'location',
        'urlSuffix' : 'locations/',
      },
      {
        'name' : 'monitorScript',
        'urlSuffix' : 'monitor_scripts/',
      },
      {
        'name' : 'monitors',
        'urlSuffix' : 'monitors/',
      },
      {
        'name' : 'persistence',
        'urlSuffix' : 'persistence/',
      },
      {
        'name' : 'pool',
        'urlSuffix' : 'pools/',
      },
      {
        'name' : 'protection',
        'urlSuffix' : 'protection/',
      },
      {
        'name' : 'rate',
        'urlSuffix' : 'rate/',
      },
      {
        'name' : 'ruleAuthenticator',
        'urlSuffix' : 'rule_authenticators/',
      },
      {
        'name' : 'rule',
        'urlSuffix' : 'rules/',
      },
      {
        'name' : 'security',
        'urlSuffix' : 'security/',
      },
      {
        'name' : 'serviceLevelMonitor',
        'urlSuffix' : 'service_level_monitors/',
      },
      {
        'name' : 'ssl',
        'urlSuffix' : 'ssl/',
      },
      {
        'name' : 'trafficIpGroup',
        'urlSuffix' : 'traffic_ip_groups/',
      },
      {
        'name' : 'userAuthenticator',
        'urlSuffix' : 'user_authenticators/',
      },
      {
        'name' : 'userGroup',
        'urlSuffix' : 'user_groups/',
      },
      {
        'name' : 'virtualServer',
        'urlSuffix' : 'virtual_servers/',
      },
    ]
    self.__requestParameters = {
      'headers': {'Content-Type': 'application/json'},
      'auth': (self.user, self.__password),
    }
    self.__requestParameters['verify'] = verify_ssl
    self.__getApiUrl()
  
  def __getResponse(self,url):
    try:
      with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = self.__session.get(url, **self.__requestParameters)
    except requests.exceptions.ConnectionError:
      # if self.toConsole:
        # sys.stderr.write(
          # "ERROR: Unable to connect to {0}".format(url)
        # )
      raise
      return False
    pattern = re.compile("^2\d{2}")
    if not pattern.match(str(response.status_code)):
      sys.stderr.write(
        "ERROR: Invalid response from {0}.  Response code: {1}".format(
          url,
          response.status_code
        ))
      return False
    if self.toConsole:
      self.__pp.pprint(response.json())
    return response.json()
  
  def __putResponse(self,config,url):
    try:
      with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = self.__session.put(
          url,data=config,**self.__requestParameters
        )
    except requests.exceptions.ConnectionError:
      # if self.toConsole:
        # sys.stderr.write(
          # "ERROR: Unable to connect to {0}".format(url)
        # )
      raise
      return False
    if response.status_code == 200:
      if self.toConsole:
        print('Modified entry successfully.')
    elif response.status_code == 201:
      if self.toConsole:
        print('Added new entry successfully. ({0})'.format(
          response.status_code
        ))
    elif response.status_code == 204:
      if self.toConsole:
        print('File updated successfully.')
      return response.status_code
    else:
      sys.stderr.write(
        "ERROR: Invalid response from {0}.  Response code: {1}".format(
          url,
          response.status_code
        ))
      return False
    return response.json()
  
  def __deleteResponse(self,url):
    try:
      with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = self.__session.delete(url,**self.__requestParameters)
    except requests.exceptions.ConnectionError:
      # if self.toConsole:
        # sys.stderr.write(
          # "ERROR: Unable to connect to {0}".format(url)
        # )
      raise
      return False
    if response.status_code == 204:
      if self.toConsole:
        print('Entry deleted successfully.')
    else:
      sys.stderr.write(
        "ERROR: Invalid response from {0}.  Response code: {1}".format(
          url,
          response.status_code
        ))
      return False
    return response.status_code
  
  def __getApiUrl(self):
    apiUrl = '{0}://{1}:{2}/api/tm/'.format(
      self.protocol,
      self.host,
      self.port,
    )
    toConsole = self.toConsole
    if toConsole:
      self.toConsole = False
    response = self.__getResponse(apiUrl)
    if toConsole:
      self.toConsole = True
    if not response:
      return False
    # Selects the last api href, which is the latest
    apiSuffix = response['children'][-1]['href']
    self.__apiVersion = response['children'][-1]['name']
    if self.toConsole:
      print('API version for {0}: {1}'.format(self.host, self.__apiVersion))
    self.__apiUrl = '{0}://{1}:{2}{3}'.format(
      self.protocol,
      self.host,
      self.port,
      apiSuffix,
    )
    return
  
  #Used to return a list of most config object types
  def getConfigType(self,type):
    typeUrlSuffix = [
      entry['urlSuffix'] for entry in self.__typeSuffixes if entry['name'] == type 
    ][0]
    #self.typeUrlSuffixes[type]
    requestUrl = '{0}{1}{2}'.format(
      self.__apiUrl,
      self.__activeConfigUrlSuffix,
      typeUrlSuffix,
    )
    response = self.__getResponse(requestUrl)
    if not response:
      return False
    return response
  
  # Copy a config entry's data structure and just change the values to create
  # something new
  def getConfigEntry(self,type,name):
    typeUrlSuffix = [
      entry['urlSuffix'] for entry in self.__typeSuffixes if entry['name'] == type 
    ][0]
    requestUrl = '{0}{1}{2}{3}'.format(
      self.__apiUrl,
      self.__activeConfigUrlSuffix,
      typeUrlSuffix,
      name,
    )
    return self.__getResponse(requestUrl)
  
  # For changing and adding an entry of the specified type
  def putConfigEntry(self,type,name,config):
    typeUrlSuffix = [
      entry['urlSuffix'] for entry in self.__typeSuffixes if entry['name'] == type 
    ][0]
    requestUrl = '{0}{1}{2}{3}'.format(
      self.__apiUrl,
      self.__activeConfigUrlSuffix,
      typeUrlSuffix,
      name,
    )
    jsonConfig = json.dumps(config)
    return self.__putResponse(jsonConfig,requestUrl)
  
  # Obviously for deleting an entry of the specified type
  def deleteConfigEntry(self,type,name):
    typeUrlSuffix = [
      entry['urlSuffix'] for entry in self.__typeSuffixes if entry['name'] == type 
    ][0]
    requestUrl = '{0}{1}{2}{3}'.format(
      self.__apiUrl,
      self.__activeConfigUrlSuffix,
      typeUrlSuffix,
      name,
    )
    return self.__deleteResponse(requestUrl)

# New structures for a given class of configurations are provided by this class.
class VtmConfig:
  def __init__(self,api_version='latest',to_console=True):
    # Update this list with any new API versions to be supported
    self.__supportedApiVersions = [3.7]
    # Add/edit this list of dicts to increase config functionality
    self.__allConfigs = [
      {
        'name' : 'actionProgram',
        'urlSuffix' : 'action_programs/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'action',
        'urlSuffix' : 'actions/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'appliance',
        'urlSuffix' : 'appliance/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'applicationFirewall',
        'urlSuffix' : 'application_firewall/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'aptimizer',
        'urlSuffix' : 'aptimizer/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'bandwidth',
        'urlSuffix' : 'bandwidth/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'bgpNeighbor',
        'urlSuffix' : 'bgpneighbors/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'cloudApiCredential',
        'urlSuffix' : 'cloud_api_credentials/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'custom',
        'urlSuffix' : 'custom/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'dnsServer',
        'urlSuffix' : 'dns_server/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'eventType',
        'urlSuffix' : 'event_types/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'extraFile',
        'urlSuffix' : 'extra_files/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'glbService',
        'urlSuffix' : 'glb_services/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'globalSetting',
        'urlSuffix' : 'global_settings/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'kerberos',
        'urlSuffix' : 'kerberos/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'licenseKey',
        'urlSuffix' : 'license_keys/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'location',
        'urlSuffix' : 'locations/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'monitorScript',
        'urlSuffix' : 'monitor_scripts/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'monitors',
        'urlSuffix' : 'monitors/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'persistence',
        'urlSuffix' : 'persistence/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'pool',
        'urlSuffix' : 'pools/',
        'config' : {
          'properties': {
            'auto_scaling': {
              'addnode_delaytime': 0,
              'cloud_credentials': '',
              'cluster': '',
              'data_center': '',
              'data_store': '',
              'enabled': False,
              'external': True,
              'hysteresis': 20,
              'imageid': '',
              'ips_to_use': 'publicips',
              'last_node_idle_time': 3600,
              'max_nodes': 4,
              'min_nodes': 1,
              'name': '',
              'port': 80,
              'refractory': 180,
              'response_time': 1000,
              'scale_down_level': 95,
              'scale_up_level': 40,
              'securitygroupids': [],
              'size_id': '',
              'subnetids': [],
            },
            'basic': {
              'bandwidth_class': '',
              'failure_pool': '',
              'max_connection_attempts': 0,
              'max_idle_connections_pernode': 50,
              'max_timed_out_connection_attempts': 2,
              'monitors': ['Ping'],
              'node_close_with_rst': False,
              'node_connection_attempts': 3,
              'node_delete_behavior': 'immediate',
              'node_drain_to_delete_timeout': 0,
              'nodes_table': [],
              'note': '',
              'passive_monitoring': True,
              'persistence_class': '',
              'transparent': False,
            },
            'connection': {
              'max_connect_time': 4,
              'max_connections_per_node': 0,
              'max_queue_size': 0,
              'max_reply_time': 30,
              'queue_timeout': 10,
            },
            'dns_autoscale': {
              'enabled': False,
              'hostnames': [],
              'port': 80,
            },
            'ftp': {'support_rfc_2428': False},
            'http': {'keepalive': True, 'keepalive_non_idempotent': False},
            'kerberos_protocol_transition': {
              'principal': '',
              'target': '',
            },
            'load_balancing': {
              'algorithm': 'round_robin',
              'priority_enabled': False,
              'priority_nodes': 1,
            },
            'node': {'close_on_death': False, 'retry_fail_time': 60},
            'smtp': {'send_starttls': True},
            'ssl': {
              'client_auth': False,
              'common_name_match': [],
              'elliptic_curves': [],
              'enable': False,
              'enhance': False,
              'send_close_alerts': True,
              'server_name': False,
              'signature_algorithms': '',
              'ssl_ciphers': '',
              'ssl_support_ssl2': 'use_default',
              'ssl_support_ssl3': 'use_default',
              'ssl_support_tls1': 'use_default',
              'ssl_support_tls1_1': 'use_default',
              'ssl_support_tls1_2': 'use_default',
              'strict_verify': False,
            },
            'tcp': {'nagle': True},
            'udp': {'accept_from': 'dest_only', 'accept_from_mask': ''},
          },
        },
        'help' : 'Requires at least one nodes_table dict having node and state \
          keys.  Nodes are strings having a colon separated IP address or \
          hostname and port',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'protection',
        'urlSuffix' : 'protection/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'rate',
        'urlSuffix' : 'rate/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'ruleAuthenticator',
        'urlSuffix' : 'rule_authenticators/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'rule',
        'urlSuffix' : 'rules/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'security',
        'urlSuffix' : 'security/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'serviceLevelMonitor',
        'urlSuffix' : 'service_level_monitors/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'ssl',
        'urlSuffix' : 'ssl/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'trafficIpGroup',
        'urlSuffix' : 'traffic_ip_groups/',
        'config' : {
          'properties': {
            'basic': {
              'enabled': True,
              'hash_source_port': False,
              'ip_assignment_mode': 'balanced',
              'ip_mapping': [],
              'ipaddresses': [],
              'keeptogether': False,
              'location': 0,
              'machines': [],
              'mode': 'singlehosted',
              'multicast': '239.101.1.14',
              'note': '',
              'rhi_bgp_metric_base': 10,
              'rhi_bgp_passive_metric_offset': 10,
              'rhi_ospfv2_metric_base': 10,
              'rhi_ospfv2_passive_metric_offset': 10,
              'rhi_protocols': 'ospf',
              'slaves': [],
            },
          },
        },
        'help' : 'Requires ipaddresses list and machines (vtm cluster member \
          hostnames) list',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'userAuthenticator',
        'urlSuffix' : 'user_authenticators/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'userGroup',
        'urlSuffix' : 'user_groups/',
        'config' : {},
        'help' : '',
        'apiVersion' : 3.7,
      },
      {
        'name' : 'virtualServer',
        'urlSuffix' : 'virtual_servers/',
        'config' : {
          'properties': {
            'aptimizer': {'enabled': False, 'profile': []},
            'basic': {
              'add_cluster_ip': True,
              'add_x_forwarded_for': False,
              'add_x_forwarded_proto': False,
              'autodetect_upgrade_headers': True,
              'bandwidth_class': '',
              'close_with_rst': False,
              'completionrules': [],
              'connect_timeout': 10,
              'enabled': True,
              'ftp_force_server_secure': True,
              'glb_services': [],
              'listen_on_any': False,
              'listen_on_hosts': [],
              'listen_on_traffic_ips': [],
              'note': '',
              'pool': '',
              'port': 80,
              'protection_class': '',
              'protocol': 'http',
              'request_rules': [],
              'response_rules': [],
              'slm_class': '',
              'so_nagle': False,
              'ssl_client_cert_headers': 'none',
              'ssl_decrypt': False,
              'ssl_honor_fallback_scsv': 'use_default',
              'transparent': False,
            },
            'connection': {
              'keepalive': True,
              'keepalive_timeout': 10,
              'max_client_buffer': 65536,
              'max_server_buffer': 65536,
              'max_transaction_duration': 0,
              'server_first_banner': '',
              'timeout': 40,
            },
            'connection_errors': {'error_file': 'Default'},
            'cookie': {
              'domain': 'no_rewrite',
              'new_domain': '',
              'path_regex': '',
              'path_replace': '',
              'secure': 'no_modify',
            },
            'dns': {
              'edns_client_subnet': True,
              'edns_udpsize': 4096,
              'max_udpsize': 4096,
              'rrset_order': 'fixed',
              'verbose': False,
              'zones': [],
            },
            'ftp': {
              'data_source_port': 0,
              'force_client_secure': True,
              'port_range_high': 0,
              'port_range_low': 0,
              'ssl_data': True,
            },
            'gzip': {
              'compress_level': 1,
              'enabled': False,
              'etag_rewrite': 'wrap',
              'include_mime': ['text/html', 'text/plain'],
              'max_size': 10000000,
              'min_size': 1000,
              'no_size': True,
            },
            'http': {
              'chunk_overhead_forwarding': 'lazy',
              'location_regex': '',
              'location_replace': '',
              'location_rewrite': 'if_host_matches',
              'mime_default': 'text/plain',
              'mime_detect': False,
            },
            'http2': {
              'connect_timeout': 0,
              'data_frame_size': 4096,
              'enabled': True,
              'header_table_size': 4096,
              'headers_index_blacklist': [],
              'headers_index_default': True,
              'headers_index_whitelist': [],
              'idle_timeout_no_streams': 120,
              'idle_timeout_open_streams': 600,
              'max_concurrent_streams': 200,
              'max_frame_size': 16384,
              'max_header_padding': 0,
              'merge_cookie_headers': True,
              'stream_window_size': 65535,
            },
            'kerberos_protocol_transition': {
              'enabled': False,
              'principal': '',
              'target': '',
            },
            'log': {
              'client_connection_failures': False,
              'enabled': False,
              'filename': '%zeushome%/zxtm/log/%v.log',
              'format': '%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"',
              'save_all': True,
              'server_connection_failures': False,
              'session_persistence_verbose': False,
              'ssl_failures': False,
            },
            'recent_connections': {'enabled': True, 'save_all': False},
            'request_tracing': {'enabled': False, 'trace_io': False},
            'rtsp': {
              'streaming_port_range_high': 0,
              'streaming_port_range_low': 0,
              'streaming_timeout': 30,
            },
            'sip': {
              'dangerous_requests': 'node',
              'follow_route': True,
              'max_connection_mem': 65536,
              'mode': 'sip_gateway',
              'rewrite_uri': False,
              'streaming_port_range_high': 0,
              'streaming_port_range_low': 0,
              'streaming_timeout': 60,
              'timeout_messages': True,
              'transaction_timeout': 30,
            },
            'smtp': {'expect_starttls': True},
            'ssl': {
              'add_http_headers': False,
              'client_cert_cas': [],
              'elliptic_curves': [],
              'issued_certs_never_expire': [],
              'ocsp_enable': False,
              'ocsp_issuers': [],
              'ocsp_max_response_age': 0,
              'ocsp_stapling': False,
              'ocsp_time_tolerance': 30,
              'ocsp_timeout': 10,
              'prefer_sslv3': False,
              'request_client_cert': 'dont_request',
              'send_close_alerts': True,
              'server_cert_default': '',
              'server_cert_host_mapping': [],
              'signature_algorithms': '',
              'ssl_ciphers': '',
              'ssl_support_ssl2': 'use_default',
              'ssl_support_ssl3': 'use_default',
              'ssl_support_tls1': 'use_default',
              'ssl_support_tls1_1': 'use_default',
              'ssl_support_tls1_2': 'use_default',
              'trust_magic': False,
            },
            'syslog': {
              'enabled': False,
              'format': '%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"',
              'ip_end_point': '',
              'msg_len_limit': 1024,
            },
            'tcp': {'proxy_close': False},
            'udp': {
              'end_point_persistence': True,
              'port_smp': False,
              'response_datagrams_expected': 1,
              'timeout': 7,
            },
            'web_cache': {
              'control_out': '',
              'enabled': False,
              'error_page_time': 30,
              'max_time': 600,
              'refresh_time': 2,
            },
          },
        },
        'help' : 'Requires listen_on_traffic_ips string as the name of one TIP,\
          and pool as the name of the default pool',
        'apiVersion' : 3.7,
      },
    ]
    self.toConsole = to_console
    if self.toConsole:
      self.__pp = PrettyPrinter(indent=2)
    if api_version == 'latest':
      api_version = self.__supportedApiVersions[-1]
    self.apiVersion = api_version
  
  def create(self,type):
    entry = [
      config for config in self.__configs 
      if config['name'] == type 
      and config['apiVersion'] == self.__apiVersion
    ][0]
    if self.toConsole:
      self.__pp.pprint(entry['config'])
      print(entry['help'])
    return entry['config']
  
  def __generateVersionConfig(self,urlSuffix,version):
    return max(
      list(filter(
        lambda x: x['urlSuffix'] == urlSuffix 
        and x['apiVersion'] <= version,
        self.__allConfigs
      )), key=lambda y: y['apiVersion']
    )
  
  @property
  def apiVersion(self):
    return self.__apiVersion
  
  @apiVersion.setter
  def apiVersion(self,version):
    self.__apiVersion = version
    if self.toConsole:
      print('Specified API version: {0}'.format(self.__apiVersion))
    # This part is pretty hard to understand, so lemme asplain.  This takes 
    # __allConfigs makes a new __configs by overlaying versions from the lowest 
    # (3.7) to whatever version is specified (latest is default) so that there 
    # is only one config structure returned for any given urlSuffix.  Configs
    # (including any changed ones from an existing url suffix) from future 
    # versions of API can be appended to __allConfigs to support that version.
    self.__configs = [
      max(list(filter(
          lambda x: x['urlSuffix'] == suffix 
          and x['apiVersion'] <= version,
          self.__allConfigs
        )), key=lambda y: y['apiVersion']
      )
      for suffix in list(set([
        config['urlSuffix'] for config in self.__allConfigs 
        if config['apiVersion'] <= version
      ]))
    ]

