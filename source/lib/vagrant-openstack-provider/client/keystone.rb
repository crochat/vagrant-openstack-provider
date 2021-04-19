require 'log4r'
require 'json'

require 'vagrant-openstack-provider/client/request_logger'

module VagrantPlugins
  module Openstack
    class KeystoneClient
      include Singleton
      include VagrantPlugins::Openstack::HttpUtils::RequestLogger

      def initialize
        @logger = Log4r::Logger.new('vagrant_openstack::keystone')
        @session = VagrantPlugins::Openstack.session
      end

      def authenticate(env)
        @logger.info('Authenticating on Keystone')
        config = env[:machine].provider_config

        if config.identity_api_version == '2'
          @logger.info(I18n.t('vagrant_openstack.client.authentication', project: config.tenant_name, user: config.username))
        elsif config.identity_api_version == '3'
          @logger.info(I18n.t('vagrant_openstack.client.authentication3', project: config.project_name, project_domain: config.project_domain_name, user: config.username, user_domain: config.user_domain_name))

          scoped = false
          if !config.project_id.nil? && !config.project_domain_name.nil?
            scoped = true
          end
        end

        if config.identity_api_version == '3' && !config.auth_type.nil?
          @logger.info("V3 Auth Type: #{config.auth_type}")
          cmd = "openstack --os-identity-api-version \"#{config.identity_api_version}\" --os-auth-type \"#{config.auth_type}\""
          debug_msg = cmd

          user_id = nil
          auth_token = nil

          if config.auth_type == 'v3oidcpassword'
            if !config.openstack_auth_url.nil? && !config.identity_provider.nil? && !config.discovery_endpoint.nil? &&
              !config.protocol.nil? && !config.client_id.nil? && !config.client_secret.nil? &&
              !config.username.nil? && !config.password.nil?
                @logger.info("Using OpenStack authentication plugin: #{config.auth_type}")
                debug_msg += " --os-auth-url \"#{config.openstack_auth_url}\" --os-identity-provider \"#{config.identity_provider}\" --os-discovery-endpoint \"#{config.discovery_endpoint}\" --os-protocol \"#{config.protocol}\" --os-client-id \"#{config.client_id}\" --os-client-secret \"#{config.client_secret}\" --os-username \"#{config.username}\" --os-password \"****\""
                cmd += " --os-auth-url \"#{config.openstack_auth_url}\" \
                        --os-identity-provider \"#{config.identity_provider}\" \
                        --os-discovery-endpoint \"#{config.discovery_endpoint}\" \
                        --os-protocol \"#{config.protocol}\" \
                        --os-client-id \"#{config.client_id}\" \
                        --os-client-secret \"#{config.client_secret}\" \
                        --os-username \"#{config.username}\" \
                        --os-password \"#{config.password}\""
            end
          end

          if scoped
            debug_msg += " --os-project-id \"#{config.project_id}\" --os-project-domain-name \"#{config.project_domain_name}\""
            cmd += " --os-project-id \"#{config.project_id}\" --os-project-domain-name \"#{config.project_domain_name}\""
          end

          debug_msg = "env -i #{debug_msg} token issue"
          @logger.debug(debug_msg)
          result = `env -i #{cmd} token issue`
          result.each_line do |line|
            line = line.chomp
            if line.include?('id')
              items = line.split('|')
              key = items[1].strip
              val = items[2].strip
              if !val.empty?
                if key == 'id'
                  auth_token = val
                elsif key == 'user_id'
                  user_id = val
                end
              end
            end
          end

          if !auth_token.nil?
            token_msg = 'Successfully got'
            if scoped
              token_msg += ' scoped'
            else
              token_msg += ' unscoped'
            end
            token_msg += ' authentication token...'
            @logger.info(token_msg)
          else
            @logger.error("Authentication using #{config.auth_type} failed!")
            fail Errors::AuthenticationFailed
          end

          if !scoped && !auth_token.nil? && !user_id.nil?
            post_body = get_body_3(config=config, method='token', token=auth_token)
            projects_url = env[:machine].provider_config.openstack_auth_url + "/users/#{user_id}/projects"

            headers = {
              content_type: :json,
              'X-Auth-Token': auth_token,
              accept: :json
            }

            @logger.info('Getting project list...')
            log_request(:GET, projects_url, '', headers)
            response_code = 0
            projects = RestUtils.get(env, projects_url, headers) do |response|
              log_response(response)
              response_code = response.code
              case response.code
              when 200
                response
              when 201
                response
              when 401
                fail Errors::AuthenticationFailed
              when 404
                fail Errors::BadAuthenticationEndpoint
              else
                fail Errors::VagrantOpenstackError, message: response.to_s
              end
            end

            if response_code == 200 || response_code == 201
              body = JSON.parse(projects)
              body['projects'].each do |project|
                if project['name'] == config.project_name
                  config.project_id = project['id']
                  break
                end
              end
            end

            if !config.project_id.nil?
              @logger.info("Found project ID: #{config.project_id}. Now we'll be able to get a scoped authentication.")
              scoped = true
              config.auth_method = 'token'
              config.auth_token = auth_token
            end
          end
        end

        if config.identity_api_version == '2'
          post_body = get_body_2 config
          auth_url = get_auth_url_2 env
        elsif config.identity_api_version == '3'
          @logger.info("Using #{config.auth_method} authentication method.")
          post_body = get_body_3(config=config, method=config.auth_method, scoped=scoped, password=config.password, token=config.auth_token)
          auth_url = get_auth_url_3 env
        end

        headers = {
          content_type: :json,
          accept: :json
        }

        log_request(:POST, auth_url, post_body.to_json, headers)

        if config.identity_api_version == '2'
          post_body[:auth][:passwordCredentials][:password] = config.password
        end

        response_code = 0
        authentication = RestUtils.post(env, auth_url, post_body.to_json, headers) do |response|
          log_response(response)
          response_code = response.code
          case response.code
          when 200
            response
          when 201
            response
          when 401
            fail Errors::AuthenticationFailed
          when 404
            fail Errors::BadAuthenticationEndpoint
          else
            fail Errors::VagrantOpenstackError, message: response.to_s
          end
        end

        result = nil
        if response_code == 200 || response_code == 201
          if config.identity_api_version == '2'
            access = JSON.parse(authentication)['access']
            response_token = access['token']
            @session.token = response_token['id']
            @session.project_id = response_token['tenant']['id']
            result = access['serviceCatalog']
          elsif config.identity_api_version == '3'
            body = JSON.parse(authentication)
            @session.token = authentication.headers[:x_subject_token]
            @session.project_id = body['token']['project']['id']
            result = body['token']['catalog']
          end
        end

        return result
      end

      private

      def get_body_2(config)
        {
          auth:
          {
            tenantName: config.tenant_name,
            passwordCredentials:
            {
              username: config.username,
              password: '****'
            }
          }
        }
      end

      def get_identity_3(config, method='password', password=nil, token=nil)
        identity = {
          methods: [method]
        }
        if method == 'password'
          identity[:password] = {
            user: {
              name: config.username,
              password: '****'
            }
          }
          if !password.nil?
            identity[:password][:user][:password] = password
          end
        elsif method == 'token'
          identity[:token] = {
            id: '****'
          }
          if !token.nil?
            identity[:token][:id] = "#{token}"
          end
        end

        identity
      end

      def get_body_3(config, method='password', scoped=false, password=nil, token=nil)
        body = {
          auth: {
            identity: get_identity_3(config=config, method=method, password=password, token=token)
          }
        }
        if scoped
          body[:auth][:scope] = {
            project: {
              id: config.project_id
            }
          }
        end

        body
      end

      def get_auth_url_3(env)
        url = env[:machine].provider_config.openstack_auth_url
        return url if url.match(%r{/tokens/*$})
        "#{url}/auth/tokens"
      end

      def get_auth_url_2(env)
        url = env[:machine].provider_config.openstack_auth_url
        return url if url.match(%r{/tokens/*$})
        "#{url}/tokens"
      end
    end
  end
end
