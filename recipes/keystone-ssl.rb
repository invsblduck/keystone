#
# Cookbook Name:: keystone
# Recipe:: keystone-ssl
#
# Copyright 2012-2013, Rackspace US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include_recipe "apache2"
include_recipe "osops-utils::mod_ssl"
include_recipe "osops-utils::ssl_packages"

# Fix haproxy configs to work with SSL
node.set['ha']['available_services']['keystone-admin-api']['lb_mode'] = 'tcp'
node.set['ha']['available_services']['keystone-service-api']['lb_mode'] = 'tcp'
node.set['ha']['available_services']['keystone-internal-api']['lb_mode'] = 'tcp'

ks_admin_bind = get_bind_endpoint("keystone", "admin-api")
ks_service_bind = get_bind_endpoint("keystone", "service-api")
ks_internal_bind = get_bind_endpoint("keystone", "internal-api")

ha_role = "openstack-ha"
vip_key = "vips.keystone-admin-api"

if get_role_count(ha_role) > 0 and rcb_safe_deref(node, vip_key)
  admin_ip = ks_admin_bind["host"]
  service_ip = ks_service_bind["host"]
  internal_ip = ks_internal_bind["host"]
else
  admin_ip = "*"
  service_ip = "*"
  internal_ip = "*"
end

# Hash for cert/key/chain file locations (per service)
certs  = {}
ssldir = node['keystone']['ssl']['dir']

# Platform stuff
case node['platform_family']
when 'debian'
  cert_group = 'ssl-cert'
  vhost_path = "#{node["apache"]["dir"]}/sites-available/openstack-keystone"
when 'rhel'
  cert_group = 'root'
  vhost_path = "#{node["apache"]["dir"]}/conf.d/openstack-keystone"
end

# Iterate each service type and populate `certs' hash, possibly creating
# default files along the way (unless user configured overrides).
#
%w{admin service internal}.each do |svc|
  # make a home for this service's file paths
  certs[svc] = {} unless certs.has_key?(svc)

  # save reference to node hash we'll use frequently
  hsh = node['keystone']['services']["#{svc}-api"]
  Chef::Log.info("hsh = #{hsh.inspect}")

  # PEM file
  if hsh.has_key?('cert_override')
    certs[svc]['cert_file'] = hsh['cert_override']
  else
    certs[svc]['cert_file'] = "#{ssldir}/certs/#{hsh['cert_file']}"
    cookbook_file certs[svc]['cert_file'] do
      source "keystone_#{svc}.pem"
      mode 0644
      owner 'root'
      group 'root'
    end
  end

  # Private key
  if hsh.has_key?('key_override')
    certs[svc]['key_file'] = hsh['key_override']
  else
    certs[svc]['key_file'] = "#{ssldir}/private/#{hsh['key_file']}"
    cookbook_file certs[svc]['key_file'] do
      source "keystone_#{svc}.key"
      mode 0644
      owner 'root'
      group cert_group
    end
  end

  # Chain file (different logic for this one)
  if hsh.has_key?('chain_file') and not hsh['chain_file'].nil?
    certs[svc]['chain_file'] = "#{ssldir}/certs/#{hsh['chain_file']}"
    cookbook_file certs[svc]['chain_file'] do
      source hsh['chain_file']
      mode 0644
      owner 'root'
      group 'root'
    end
  else
    certs[svc]['chain_file'] = 'donotset'
  end
end

# Create Apache vhost
# TODO(brett): can this be generalized for apache LWRPs?
template vhost_path do
  source "keystone_ssl_vhost.erb"
  owner "root"
  group "root"
  mode "0644"
  variables(
    :admin_ip => admin_ip,
    :admin_scheme => node["keystone"]["services"]["admin-api"]["scheme"],
    :admin_port => node["keystone"]["services"]["admin-api"]["port"],
    :admin_cert_file => certs['admin']['cert_file'],
    :admin_key_file => certs['admin']['key_file'],
    :admin_chain_file => certs['admin']['chain_file'],

    :service_ip => service_ip,
    :service_scheme => node["keystone"]["services"]["service-api"]["scheme"],
    :service_port => node["keystone"]["services"]["service-api"]["port"],
    :service_cert_file => certs['service']['cert_file'],
    :service_key_file => certs['service']['key_file'],
    :service_chain_file => certs['service']['chain_file'],

    :internal_ip => internal_ip,
    :internal_scheme => node["keystone"]["services"]["internal-api"]["scheme"],
    :internal_port => node["keystone"]["services"]["internal-api"]["port"],
    :internal_cert_file => certs['internal']['cert_file'],
    :internal_key_file => certs['internal']['key_file'],
    :internal_chain_file => certs['internal']['chain_file']
  )
  #notifies :run, "execute[Keystone: sleep]", :immediately
  #notifies :restart, "service[apache2]", :immediately
  notifies :restart, "service[apache2]"
end

apache_module 'proxy_http' do
  enable true
end

apache_site "openstack-keystone" do
  enable true
end

service "apache2" do
  action :restart
end

if get_role_count("openstack-ha") > 0 and rcb_safe_deref(node, "vips.keystone-admin-api")
  include_recipe "openstack-ha::default"
  service "haproxy" do
    action :restart
  end
end

