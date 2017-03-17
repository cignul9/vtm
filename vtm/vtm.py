#!/usr/bin/env python
import requests
import json
import sys
import warnings
from pprint import PrettyPrinter
from distutils.version import StrictVersion
import re

class VtmConnection:
    '''
    Facilitates interacting with an instance of Virtual Traffic Manager 
    (Stingray)
    '''
    def __init__(
            self,
            host,
            user,
            password,
            protocol='https',
            port=9070,
            verify_ssl=False,
            to_console=True,
    ):
        self.user = user
        self.__password = password
        self.host = host
        self.protocol = protocol
        self.port = port
        self.__session = requests.Session()
        self.__auth = (self.user, self.__password)
        self.__pp = PrettyPrinter(indent=2)
        self.__to_console = to_console
        self.to_console = self.__to_console
        self.__active_config_url_suffix = 'config/active/'
        self.__type_suffixes = [
            {
                'name': 'action_program',
                'url_suffix': 'action_programs/',
            },
            {
                'name': 'action',
                'url_suffix': 'actions/',
            },
            {
                'name': 'appliance',
                'url_suffix': 'appliance/',
            },
            {
                'name': 'application_firewall',
                'url_suffix': 'application_firewall/',
            },
            {
                'name': 'aptimizer',
                'url_suffix': 'aptimizer/',
            },
            {
                'name': 'bandwidth',
                'url_suffix': 'bandwidth/',
            },
            {
                'name': 'bgp_neighbor',
                'url_suffix': 'bgpneighbors/',
            },
            {
                'name': 'cloud_api_credential',
                'url_suffix': 'cloud_api_credentials/',
            },
            {
                'name': 'custom',
                'url_suffix': 'custom/',
            },
            {
                'name': 'dns_server',
                'url_suffix': 'dns_server/',
            },
            {
                'name': 'event_type',
                'url_suffix': 'event_types/',
            },
            {
                'name': 'extra_file',
                'url_suffix': 'extra_files/',
            },
            {
                'name': 'glb_service',
                'url_suffix': 'glb_services/'
            },
            {
                'name': 'global_setting',
                'url_suffix': 'global_settings/',
            },
            {
                'name': 'kerberos',
                'url_suffix': 'kerberos/',
            },
            {
                'name': 'license_key',
                'url_suffix': 'license_keys/',
            },
            {
                'name': 'location',
                'url_suffix': 'locations/',
            },
            {
                'name': 'monitor_script',
                'url_suffix': 'monitor_scripts/',
            },
            {
                'name': 'monitors',
                'url_suffix': 'monitors/',
            },
            {
                'name': 'persistence',
                'url_suffix': 'persistence/',
            },
            {
                'name': 'pool',
                'url_suffix': 'pools/',
            },
            {
                'name': 'protection',
                'url_suffix': 'protection/',
            },
            {
                'name': 'rate',
                'url_suffix': 'rate/',
            },
            {
                'name': 'rule_authenticator',
                'url_suffix': 'rule_authenticators/',
            },
            {
                'name': 'rule',
                'url_suffix': 'rules/',
            },
            {
                'name': 'security',
                'url_suffix': 'security/',
            },
            {
                'name': 'service_level_monitor',
                'url_suffix': 'service_level_monitors/',
            },
            {
                'name': 'ssl',
                'url_suffix': 'ssl/',
            },
            {
                'name': 'traffic_ip_group',
                'url_suffix': 'traffic_ip_groups/',
            },
            {
                'name': 'user_authenticator',
                'url_suffix': 'user_authenticators/',
            },
            {
                'name': 'user_group',
                'url_suffix': 'user_groups/',
            },
            {
                'name': 'virtual_server',
                'url_suffix': 'virtual_servers/',
            },
        ]
        self.__request_parameters = dict(
          headers={'Content-Type': 'application/json'},
          auth=(self.user, self.__password),
        )
        self.__request_parameters['verify'] = verify_ssl
        self.__api_version = None
        self.__api_url = self.api_url
    
    def __get_response(self, url):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                response = self.__session.get(url, **self.__request_parameters)
        except requests.exceptions.ConnectionError:
            raise
        if response.status_code == 404:
            return False
        pattern = re.compile("^2\d{2}")
        if not pattern.match(str(response.status_code)):
            sys.stderr.write(
                "ERROR: Invalid response from {0}.  Response code: {1}".format(
                    url,
                    response.status_code
            ))
            return False
        if response.headers.get('content-type') == 'application/json':
            returned_response = response.json()
        elif response.headers.get('content-type') == 'application/octet-stream':
            returned_response = response.text
        else:
            sys.stderr.write(
                "ERROR: Invalid content-type from {0}.  : {1}".format(
                    url,
                    response.headers.get('content-type')
            ))
            return False
        if self.to_console:
            self.__pp.pprint(returned_response)
        return returned_response
    
    def __put_response(self, config, url, content_type='application/json'):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                params = self.__request_parameters
                params['headers'] = {'Content-Type': content_type}
                response = self.__session.put(
                    url, data=config, **params
                )
        except requests.exceptions.ConnectionError:
            raise
        if response.status_code == 200:
            if self.to_console:
                print('Modified entry successfully.')
        elif response.status_code == 201:
            if self.to_console:
                print('Added new entry successfully. ({0})'.format(
                    response.status_code
                ))
        elif response.status_code == 204:
            if self.to_console:
                print('File updated successfully.')
            return response.status_code
        else:
            sys.stderr.write(
                "ERROR: Invalid response from {0}.  Response code: {1}".format(
                    url,
                    response.status_code
            ))
            return False
        if response.headers.get('content-type') == 'application/json':
            returned_response = response.json()
        elif response.headers.get('content-type') == 'application/octet-stream':
            returned_response = response.text
        else:
            returned_response={}
        return returned_response
    
    def __delete_response(self, url):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                response = self.__session.delete(
                  url, **self.__request_parameters
                )
        except requests.exceptions.ConnectionError:
            raise
        if response.status_code == 204:
            if self.to_console:
                print('Entry deleted successfully.')
        else:
            sys.stderr.write(
                "ERROR: Invalid response from {0}.  Response code: {1}".format(
                    url,
                    response.status_code
            ))
            return False
        return response.status_code
    
    @property
    def to_console(self):
        return self.__to_console
    
    @to_console.setter
    def to_console(self, to_console):
        self.__to_console = to_console
        return
    
    @property
    def api_version(self):
        return self.__api_version
        
    @api_version.setter
    def api_version(self,version):
        self.__api_version = version
        return
    
    @property
    def api_url(self):
        api_url = '{0}://{1}:{2}/api/tm/'.format(
            self.protocol,
            self.host,
            self.port,
        )
        toggle_console = self.to_console
        if toggle_console:
            self.to_console = False
        response = self.__get_response(api_url)
        if toggle_console:
            self.to_console = True
        if not response:
            return False
        self.api_version = '0.0'
        for version in response['children']:
            if StrictVersion(version['name']) > StrictVersion(self.api_version ):
                self.api_version = version['name']
                api_suffix = version['href']
        if self.to_console:
            print('API version for {0}: {1}'.format(
              self.host, self.api_version
            ))
        return '{0}://{1}:{2}{3}'.format(
            self.protocol,
            self.host,
            self.port,
            api_suffix,
        )
    
    # Used to return a list of most config object types
    def get_config_type(self, config_type):
        type_url_suffix = [
            entry['url_suffix'] for entry in self.__type_suffixes
            if entry['name'] == config_type
            ][0]
        request_url = '{0}{1}{2}'.format(
            self.__api_url,
            self.__active_config_url_suffix,
            type_url_suffix,
        )
        response = self.__get_response(request_url)
        if not response:
            return False
        return response
    
    # Copy a config entry's data structure and just change the values to create
    # something new
    def get_config(self, config_type, name):
        type_url_suffix = [
            entry['url_suffix'] for entry in self.__type_suffixes
            if entry['name'] == config_type
        ][0]
        request_url = '{0}{1}{2}{3}'.format(
            self.__api_url,
            self.__active_config_url_suffix,
            type_url_suffix,
            name,
        )
        return self.__get_response(request_url)
    
    # For changing and adding an entry of the specified type
    def put_config(self, config_type, name, config):
        type_url_suffix = [
            entry['url_suffix'] for entry in self.__type_suffixes
            if entry['name'] == config_type
        ][0]
        request_url = '{0}{1}{2}{3}'.format(
            self.__api_url,
            self.__active_config_url_suffix,
            type_url_suffix,
            name,
        )
        if type(config) is dict:
            return self.__put_response(json.dumps(config), request_url)
        elif type(config) is str:
            return self.__put_response(config, request_url, 'application/octet-stream')
        else:
            sys.stderr.write("ERROR: Unexpected config type")
            return False
        
    
    # For deleting an entry of the specified type
    def delete_config(self, config_type, name):
        type_url_suffix = [
            entry['url_suffix'] for entry in self.__type_suffixes
            if entry['name'] == config_type
        ][0]
        request_url = '{0}{1}{2}{3}'.format(
            self.__api_url,
            self.__active_config_url_suffix,
            type_url_suffix,
            name,
        )
        return self.__delete_response(request_url)


class VtmConfig:
    '''
    Provides new default state VTM configuration data structures for a given 
    type
    '''
    def __init__(self, api_version='latest', config_type='', to_console=True):
        # Add/edit this list of dicts to increase config functionality
        self.__all_configs = [
            {
                'name': 'action_program',
                'url_suffix': 'action_programs/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'action',
                'url_suffix': 'actions/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'appliance',
                'url_suffix': 'appliance/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'application_firewall',
                'url_suffix': 'application_firewall/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'aptimizer',
                'url_suffix': 'aptimizer/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'bandwidth',
                'url_suffix': 'bandwidth/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'bgp_neighbor',
                'url_suffix': 'bgpneighbors/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'cloud_api_credential',
                'url_suffix': 'cloud_api_credentials/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'custom',
                'url_suffix': 'custom/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'dns_server',
                'url_suffix': 'dns_server/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'event_type',
                'url_suffix': 'event_types/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'extra_file',
                'url_suffix': 'extra_files/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'glb_service',
                'url_suffix': 'glb_services/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'global_setting',
                'url_suffix': 'global_settings/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'kerberos',
                'url_suffix': 'kerberos/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'license_key',
                'url_suffix': 'license_keys/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'location',
                'url_suffix': 'locations/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'monitor_script',
                'url_suffix': 'monitor_scripts/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'monitor',
                'url_suffix': 'monitors/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'persistence',
                'url_suffix': 'persistence/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'pool',
                'url_suffix': 'pools/',
                'config': {
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
                        'http': {
                            'keepalive': True,
                            'keepalive_non_idempotent': False
                        },
                        'kerberos_protocol_transition': {
                            'principal': '',
                            'target': '',
                        },
                        'load_balancing': {
                            'algorithm': 'round_robin',
                            'priority_enabled': False,
                            'priority_nodes': 1,
                        },
                        'node': {
                            'close_on_death': False,
                            'retry_fail_time': 60
                        },
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
                        'udp': {
                            'accept_from': 'dest_only',
                            'accept_from_mask': ''
                        },
                    },
                },
                'help': 'Requires at least one nodes_table dict having node \
and state keys.  Nodes are strings having a colon separated IP address or \
hostname and port',
                'api_version': 3.7,
            },
            {
                'name': 'protection',
                'url_suffix': 'protection/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'rate',
                'url_suffix': 'rate/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'rule_authenticator',
                'url_suffix': 'rule_authenticators/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'rule',
                'url_suffix': 'rules/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'security',
                'url_suffix': 'security/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'service_level_monitor',
                'url_suffix': 'service_level_monitors/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'ssl',
                'url_suffix': 'ssl/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'traffic_ip_group',
                'url_suffix': 'traffic_ip_groups/',
                'config': {
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
                'help': 'Requires ipaddresses list and machines (vtm cluster \
member hostnames) list',
                'api_version': 3.7,
            },
            {
                'name': 'user_authenticator',
                'url_suffix': 'user_authenticators/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'user_group',
                'url_suffix': 'user_groups/',
                'config': {},
                'help': '',
                'api_version': 3.7,
            },
            {
                'name': 'virtual_server',
                'url_suffix': 'virtual_servers/',
                'config': {
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
                            'format': '%h %l %u %t "%r" %s %b "%{Referer}i" \
"%{User-agent}i"',
                            'save_all': True,
                            'server_connection_failures': False,
                            'session_persistence_verbose': False,
                            'ssl_failures': False,
                        },
                        'recent_connections': {
                          'enabled': True, 'save_all': False
                        },
                        'request_tracing': {
                          'enabled': False, 'trace_io': False
                        },
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
                            'format': '%h %l %u %t "%r" %s %b "%{Referer}i" \
"%{User-agent}i"',
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
                'help': 'Requires listen_on_traffic_ips string as the name of \
one TIP, and pool as the name of the default pool',
                'api_version': 3.7,
            },
        ]
        self.__pp = PrettyPrinter(indent=2)
        self.__to_console = to_console
        self.to_console = self.__to_console
        self.__config = {}
        self.__config_type = config_type
        if api_version == 'latest':
            api_version = sorted(set(
                [config['api_version'] for config in self.__all_configs]),
                reverse=True
            )[0]
        self.__api_version = api_version
        self.api_version = self.__api_version
        self.config_type = self.__config_type
        self.__url_suffix = ''
        self.__help = ''
    
    @property
    def to_console(self):
        return self.__to_console
    
    @to_console.setter
    def to_console(self, to_console):
        self.__to_console = to_console
        return
    
    @property
    def api_version(self):
        return self.__api_version
    
    @api_version.setter
    def api_version(self, version):
        self.__api_version = version
        self.config_type = self.__config_type
    
    @property
    def config_type(self):
        return self.__config_type
    
    @config_type.setter
    def config_type(self, name):
        if not name:
            self.__config_type = ''
            return
        entry = {}
        try:
            entry = sorted([
                config for config in self.__all_configs
                if config['name'] == name and
                config['api_version'] <= self.__api_version
            ], key=lambda k: k['api_version'], reverse=True)[0]
        except IndexError:
            sys.stderr.write('Config entry type not found for the given \
version or earlier. {0}\n'.format(
                self.config_type,
            ))
        self.__config = entry['config']
        self.__config_type = name
        self.__help = entry['help']
        self.__url_suffix = entry['url_suffix']
    
    @property
    def config(self):
        if self.to_console:
            self.__pp.pprint(self.__config)
        return self.__config
    
    @property
    def help(self):
        return self.__help
    
    @property
    def url_suffix(self):
        return self.__url_suffix
