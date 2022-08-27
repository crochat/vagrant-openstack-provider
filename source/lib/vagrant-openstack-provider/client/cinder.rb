require 'log4r'
require 'json'

require 'vagrant-openstack-provider/client/http_utils'
require 'vagrant-openstack-provider/client/domain'

module VagrantPlugins
  module Openstack
    class CinderClient
      include Singleton
      include VagrantPlugins::Openstack::HttpUtils
      include VagrantPlugins::Openstack::Domain

      def initialize
        @logger = Log4r::Logger.new('vagrant_openstack::cinder')
        @session = VagrantPlugins::Openstack.session
      end

      def get_all_volumes(env)
        endpoint = @session.endpoints[:volumev2] || @session.endpoints[:volume]
        volumes_json = get(env, "#{endpoint}/volumes/detail")
        JSON.parse(volumes_json)['volumes'].map do |volume|
          name = volume['display_name']
          name = volume['name'] if name.nil? # To be compatible with cinder api v1 and v2
          case volume['attachments'].size
          when 0
            @logger.debug "No attachment found for volume #{volume['id']}"
          else
            attachment = volume['attachments'][0]
            server_id = attachment['server_id']
            device = attachment['device']
            @logger.warn "Found #{attachment.size} attachments for volume #{volume['id']} : " if attachment.size > 1
            @logger.debug "Attachment found for volume #{volume['id']} : #{attachment.to_json}"
          end
          Volume.new(volume['id'], name, volume['size'], volume['status'], volume['bootable'], server_id, device)
        end
      end

      def get_volume_types(env)
        if @session.endpoints.key? :volumev3
          volume_types_json = get(env, "#{@session.endpoints[:volumev3]}/types")
          JSON.parse(volume_types_json)['volume_types'].map do |volume_type|
            extra_specs = volume_type.key(:extra_specs)? volume_type['extra_specs'] : nil
            qos_specs_id = volume_type.key(:qos_specs_id)? volume_type['qos_specs_id'] : nil
            VolumeType.new(volume_type['id'], volume_type['name'], volume_type['description'], extra_specs, qos_specs_id)
          end
        end
      end

      def create_boot_volume(env, options)
        if @session.endpoints.key? :volumev3
          if options[:volume_boot].key? :volume_type
            unless options[:volume_boot][:image].nil?
              volume_type_id = nil
              get_volume_types(env).each do |volume_type|
                if volume_type.name == options[:volume_boot][:volume_type]
                  volume_type_id = volume_type.id
                end
              end

              volume = {}.tap do |v|
                v['size'] = options[:volume_boot][:size]
                v['availability_zone'] = nil
                v['description'] = nil
                v['multiattach'] = false
                v['snapshot_id'] = nil
                v['backup_id'] = nil
                v['name'] = options[:name]
                v['imageRef'] = options[:volume_boot][:image]
                v['volume_type'] = volume_type_id
                v['metadata'] = {}
                v['consistencygroup_id'] = nil
              end
              object = { volume: volume }
              volume = post(env, "#{@session.endpoints[:volumev3]}/volumes", object.to_json)
              JSON.parse(volume)['volume']['id']
            end
          end
        end
      end

      def get_volume_details(env, volume_id)
        instance_exists do
          volume_details = get(env, "#{@session.endpoints[:volumev3]}/volumes/#{volume_id}")
          JSON.parse(volume_details)['volume']
        end
      end

      private

      def instance_exists
        return yield
      rescue Errors::VagrantOpenstackError => e
        raise Errors::InstanceNotFound if e.extra_data[:code] == 404
        raise e
      end
    end
  end
end
