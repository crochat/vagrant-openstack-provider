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

      def waiting_for_status(env, item_type, id, status, retry_interval = 3, timeout = 180)
        result = false
        if @session.endpoints.key? :volumev3
          cycles = timeout / retry_interval
          quit = false
          until quit
            @logger.debug "Waiting for #{item_type} ID #{id} to be #{status}..."
            current_json = get(env, "#{@session.endpoints[:volumev3]}/#{item_type}s/#{id}")
            current_status = JSON.parse(current_json)[item_type]['status']
            @logger.debug "#{item_type} ID #{id} is currently #{current_status}"
            if current_status.downcase == status.downcase
              result = true
              quit = true
            else
              cycles = cycles - 1
              if cycles > 0
                sleep retry_interval
              else
                @logger.error "#{timeout} seconds timeout occured while waiting for #{item_type} ID #{id} to be #{status}!"
                quit = true
              end
            end
          end
        end

        result
      end

      def waiting_for_deletion(env, item_type, id, retry_interval = 3, timeout = 180)
        result = false
        if @session.endpoints.key? :volumev3
          cycles = timeout / retry_interval
          quit = false
          until quit
            @logger.debug "Waiting for #{item_type} ID #{id} to be deleted..."
            begin
              instance_exists do
                current_json = get(env, "#{@session.endpoints[:volumev3]}/#{item_type}s/#{id}")
                current_status = JSON.parse(current_json)[item_type]['status']
                @logger.debug "#{item_type} ID #{id} is currently #{current_status}"
              end
            rescue
              result = true
              quit = true
            end

            cycles = cycles - 1
            if cycles > 0
              sleep retry_interval
            else
              @logger.error "#{timeout} seconds timeout occured while waiting for #{item_type} ID #{id} to be #{status}!"
              quit = true
            end
          end
        end

        result
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

      def get_all_snapshots(env, volume_id=nil)
        if @session.endpoints.key? :volumev3
          snapshots_json = get(env, "#{@session.endpoints[:volumev3]}/snapshots/detail")
          JSON.parse(snapshots_json)['snapshots'].map do |vs|
            go_ahead = false
            if volume_id.nil?
              go_ahead = true
            else
              if vs['id'] == volume_id
                go_ahead = true
              end
            end

            vs_name = nil
            if vs.key? :name
              vs_name = vs['name']
            end
            vs_snapshot_links = nil
            if vs.key? :snapshot_links
              vs_snapshot_links = vs['snapshot_links']
            end
            vs_consumes_quota = nil
            if vs.key? :consumes_quota
              vs_consumes_quota = vs['consumes_quota']
            end

            VolumeSnapshot.new(
              vs['id'],
              vs['status'],
              vs['description'],
              vs['created_at'],
              vs['updated_at'],
              vs['user_id'],
              vs['volume_id'],
              vs['size'],
              vs['metadata'],
              vs['group_snapshot_id'],
              vs_name,
              vs_snapshot_links,
              vs_consumes_quota
            ) if go_ahead
          end
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
              volume_type = options[:volume_boot][:volume_type]
              volume_type_id = nil
              volume_types = get_volume_types(env)
              volume_types.each do |vt|
                if vt.name == volume_type
                  volume_type_id = vt.id
                end
              end

              unless volume_type_id.nil?
                volume = {}.tap do |v|
                  v['size'] = options[:volume_boot][:size]
                  v['availability_zone'] = nil
                  v['description'] = nil
                  v['multiattach'] = false
                  v['snapshot_id'] = nil
                  v['backup_id'] = nil
                  v['name'] = options[:name]
                  v['imageRef'] = options[:volume_boot][:image]
                  v['metadata'] = {}
                  v['consistencygroup_id'] = nil
                end
                object = { volume: volume }
                env[:ui].info("Creating new volume: #{object.to_json}")
                volume = post(env, "#{@session.endpoints[:volumev3]}/volumes", object.to_json)
                volume = JSON.parse(volume)['volume']

                if not waiting_for_status(env, 'volume', volume['id'], 'AVAILABLE')
                  @logger.error("There was an issue while waiting for volume ID #{volume['id']} to be AVAILABLE! Deleting volume ID #{volume['id']}!")
                  delete_volume(env, volume['id'])
                  fail Errors::Timeout
                end

                if volume_type != volume['volume_type']
                  env[:ui].info("Need to migrate volume ID #{volume['id']} type from #{volume['volume_type']} to #{volume_type}. This may take a while (typically more than 10 minutes for a 40 GB volume)...")
                  env[:ui].info("Creating new snapshot from volume ID #{volume['id']}")
                  snapshot_id = create_snapshot(env, volume['id'], "#{options[:name]}.tmp")['id']
                  if not waiting_for_status(env, 'snapshot', snapshot_id, 'AVAILABLE')
                    @logger.error("There was an issue while waiting for snapshot ID #{snapshot_id} to be AVAILABLE! Deleting snapshot ID #{snapshot_id} and volume ID #{volume['id']}!")
                    delete_snapshot(env, snapshot_id)
                    delete_volume(env, volume['id'])
                    fail Errors::Timeout
                  end
                  @logger.error("Snapshot ID #{snapshot_id} created successfully")

                  new_volume = {}.tap do |v|
                    v['size'] = options[:volume_boot][:size]
                    v['availability_zone'] = nil
                    v['description'] = nil
                    v['multiattach'] = false
                    v['snapshot_id'] = snapshot_id
                    v['backup_id'] = nil
                    v['name'] = options[:name]
                    v['imageRef'] = nil
                    v['metadata'] = {}
                    v['consistencygroup_id'] = nil
                  end
                  object = { volume: new_volume }
                  env[:ui].info("Creating new volume from snapshot ID #{snapshot_id}: #{object.to_json}")
                  new_volume = post(env, "#{@session.endpoints[:volumev3]}/volumes", object.to_json)
                  new_volume = JSON.parse(new_volume)['volume']

                  if not waiting_for_status(env, 'volume', new_volume['id'], 'AVAILABLE')
                    @logger.error("There was an issue while waiting for new volume ID #{new_volume['id']} to be AVAILABLE! Deleting new volume ID #{new_volume['id']}, snapshot ID #{snapshot_id}, and volume ID #{volume['id']}!")
                    delete_volume(env, new_volume['id'])
                    delete_snapshot(env, snapshot_id)
                    delete_volume(env, volume['id'])
                    fail Errors::Timeout
                  end

                  env[:ui].info("New volume ID #{new_volume['id']} created successfully. Now deleting snapshot ID #{snapshot_id} and volume ID #{volume['id']}")
                  delete_snapshot(env, snapshot_id)
                  delete_volume(env, volume['id'])

                  env[:ui].info("Retyping new volume ID #{new_volume['id']} from #{new_volume['volume_type']} to #{volume_type}. This may take a while...")
                  retype_volume(env, new_volume['id'], volume_type_id)

                  if not waiting_for_status(env, 'volume', new_volume['id'], 'AVAILABLE', 30, 1800)
                    @logger.error("There was an issue while waiting for new volume ID #{new_volume['id']} to be AVAILABLE! Deleting new volume ID #{new_volume['id']}!")
                    delete_volume(env, new_volume['id'])
                    fail Errors::Timeout
                  end

                  @logger.info("New volume ID #{new_volume['id']} successfully retyped")
                  volume = new_volume
                end

                volume['id']
              else
                if not volume_types.nil?
                  fail Errors::BadVolumeType, volume_types: volume_types.map {|t| t.name if t.name != '__DEFAULT__'}.compact.join(', ')
                end
              end
            end
          end
        end
      end

      def delete_volume(env, volume_id)
        instance_exists do
          if @session.endpoints.key? :volumev3
            delete(env, "#{@session.endpoints[:volumev3]}/volumes/#{volume_id}")
            waiting_for_deletion(env, 'volume', volume_id)
          end
        end
      end

      def get_volume_details(env, volume_id)
        if @session.endpoints.key? :volumev3
          instance_exists do
            volume_details = get(env, "#{@session.endpoints[:volumev3]}/volumes/#{volume_id}")
            JSON.parse(volume_details)['volume']
          end
        end
      end

      def retype_volume(env, volume_id, volume_type)
        if @session.endpoints.key? :volumev3
          instance_exists do
            volume = post(
              env,
              "#{@session.endpoints[:volumev3]}/volumes/#{volume_id}/action",
              { 'os-retype': {
                  'new_type': volume_type,
                  'migration_policy': 'on-demand'
                }
              }.to_json
            )
          end
        end
      end

      def list_snapshots(env, volume_id)
        if @session.endpoints.key? :volumev3
          get_all_snapshots(env, volume_id)
        end
      end

      def create_snapshot(env, volume_id, snapshot_name)
        if @session.endpoints.key? :volumev3
          instance_exists do
            snapshot = post(
              env,
              "#{@session.endpoints[:volumev3]}/snapshots",
              { snapshot: {
                  name: snapshot_name,
                  volume_id: volume_id,
                  force: true
                }
              }.to_json
            )

            JSON.parse(snapshot)['snapshot']
          end
        end
      end

      def delete_snapshot(env, snapshot_id)
        if @session.endpoints.key? :volumev3
          delete(env, "#{@session.endpoints[:volumev3]}/snapshots/#{snapshot_id}")
          waiting_for_deletion(env, 'snapshot', snapshot_id)
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
