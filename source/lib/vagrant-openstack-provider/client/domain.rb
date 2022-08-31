require 'log4r'
require 'json'

module VagrantPlugins
  module Openstack
    module Domain
      class Item
        attr_accessor :id, :name
        def initialize(id, name)
          @id = id
          @name = name
        end

        def ==(other)
          other.class == self.class && other.state == state
        end

        def state
          [@id, @name]
        end
      end

      class Image < Item
        attr_accessor :visibility
        attr_accessor :size
        attr_accessor :min_ram
        attr_accessor :min_disk
        attr_accessor :metadata

        # rubocop:disable Metrics/ParameterLists
        def initialize(id, name, visibility = nil, size = nil, min_ram = nil, min_disk = nil, metadata = {})
          @visibility = visibility
          @size = size
          @min_ram = min_ram
          @min_disk = min_disk
          @metadata = metadata
          super(id, name)
        end
        # rubocop:enable Metrics/ParameterLists

        protected

        def state
          [@id, @name, @visibility, @size, @min_ram, @min_disk, @metadata]
        end
      end

      class Flavor < Item
        #
        # The number of vCPU
        #
        attr_accessor :vcpus

        #
        # The amount of RAM in Megaoctet
        #
        attr_accessor :ram

        #
        # The size of root disk in Gigaoctet
        #
        attr_accessor :disk

        def initialize(id, name, vcpus, ram, disk)
          @vcpus = vcpus
          @ram  = ram
          @disk = disk
          super(id, name)
        end

        protected

        def state
          [@id, @name, @vcpus, @ram, @disk]
        end
      end

      class FloatingIP
        attr_accessor :ip, :pool, :instance_id
        def initialize(ip, pool, instance_id)
          @ip = ip
          @pool = pool
          @instance_id = instance_id
        end
      end

      class VolumeType < Item
        #
        # Description
        #
        attr_accessor :description

        #
        # Whether the volume type is publicly visible
        #
        attr_accessor :is_public

        #
        # Extra specs
        #
        attr_accessor :extra_specs

        #
        # The QoS specifications ID
        #
        attr_accessor :qos_specs_id

        # rubocop:disable Metrics/ParameterLists
        def initialize(id, name, description, is_public, extra_specs=nil, qos_specs_id=nil)
          @description = description
          @is_public = is_public
          @extra_specs = extra_specs
          @qos_specs_id = qos_specs_id
          super(id, name)
        end
        # rubocop:enable Metrics/ParameterLists

        def to_s
          {
            id: @id,
            name: @name,
            description: @description,
            is_public: @is_public,
            extra_specs: @extra_specs,
            qos_specs_id: @qos_specs_id
          }.to_json
        end

        protected

        def state
          [@id, @name, @description, @is_public, @extra_specs, @qos_specs_id]
        end
      end

      class VolumeSnapshot < Item
        #
        # The snapshot UUID
        #
        attr_accessor :id

        #
        # The status of the volume snapshot (e.g. 'Available', 'In-use')
        #
        attr_accessor :status

        #
        # A description for the volume snapshot
        #
        attr_accessor :description

        #
        # The date and time when the resource was created (ISO 8601)
        #
        attr_accessor :created_at

        #
        # The date and time when the resource was updated (ISO 8601)
        #
        attr_accessor :updated_at

        #
        # The UUID of the user
        #
        attr_accessor :user_id

        #
        # If the snapshot was created from a volume, the volume ID
        #
        attr_accessor :volume_id

        #
        # The size of the volume snapshot
        #
        attr_accessor :size

        #
        # One or more metadata key and value pairs for the volume snapshot, if any
        #
        attr_accessor :metadata

        #
        # The ID of the group volume snapshot
        #
        attr_accessor :group_snapshot_id

        #
        # The name of the object (optional)
        #
        attr_accessor :name

        #
        # Links for the volume snapshot (optional)
        #
        attr_accessor :snapshot_links

        #
        # Whether this resource consumes quota or not. Resources that not counted for quota usage are usually temporary internal resources created to perform an operation (optional)
        #
        attr_accessor :consumes_quota


        # rubocop:disable Metrics/ParameterLists
        def initialize(id, status, description, created_at, updated_at, user_id, volume_id, size, metadata, group_snapshot_id, name=nil, snapshot_links=nil, consumes_quota=nil)
          @id = id
          @status = status
          @description = description
          @created_at = created_at
          @updated_at = updated_at
          @user_id = user_id
          @volume_id = volume_id
          @size = size
          @metadata = metadata
          @group_snapshot_id = group_snapshot_id
          @name = name
          @snapshot_links = snapshot_links
          @consumes_quota = consumes_quota
          super(id, name)
        end
        # rubocop:enable Metrics/ParameterLists

        def to_s
          {
            id: @id,
            status: @status,
            description: @description,
            created_at: @created_at,
            updated_at: @updated_at,
            user_id: @user_id,
            size: @size,
            metadata: @metadata,
            group_snapshot_id: @group_snapshot_id,
            name: @name,
            snapshot_links: @snapshot_links,
            consumes_quota: @consumes_quota
          }.to_json
        end

        protected

        def state
          [@id, @status, @description, @created_at, @updated_at, @user_id, @size, @metadata, @group_snapshot_id, @name, @snapshot_links, @consumes_quota]
        end
      end

      class Volume < Item
        #
        # Size in Gigaoctet
        #
        attr_accessor :size

        #
        # Status (e.g. 'Available', 'In-use')
        #
        attr_accessor :status

        #
        # Whether volume is bootable or not
        #
        attr_accessor :bootable

        #
        # instance id volume is attached to
        #
        attr_accessor :instance_id

        #
        # device (e.g. /dev/sdb) if attached
        #
        attr_accessor :device

        #
        # Storage type
        #
        attr_accessor :volume_type

        # rubocop:disable Metrics/ParameterLists
        def initialize(id, name, size, status, bootable, instance_id, device, volume_type=nil)
          @size = size
          @status = status
          @bootable = bootable
          @instance_id = instance_id
          @device = device
          @volume_type = volume_type
          super(id, name)
        end
        # rubocop:enable Metrics/ParameterLists

        def to_s
          {
            id: @id,
            name: @name,
            size: @size,
            status: @status,
            bootable: @bootable,
            instance_id: @instance_id,
            device: @device,
            volume_type: @volume_type
          }.to_json
        end

        protected

        def state
          [@id, @name, @size, @status, @bootable, @instance_id, @device, @volume_type]
        end
      end

      class Subnet < Item
        attr_accessor :cidr
        attr_accessor :enable_dhcp
        attr_accessor :network_id

        def initialize(id, name, cidr, enable_dhcp, network_id)
          @cidr = cidr
          @enable_dhcp = enable_dhcp
          @network_id = network_id
          super(id, name)
        end

        protected

        def state
          [@id, @name, @cidr, @enable_dhcp, @network_id]
        end
      end
    end
  end
end
