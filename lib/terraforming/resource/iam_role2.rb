module Terraforming
  module Resource
    class IAMRole2
      include Terraforming::Util

      def self.tf(client: Aws::IAM::Client.new)
        self.new(client).tf
      end

      def self.tfstate(client: Aws::IAM::Client.new)
        self.new(client).tfstate
      end

      def initialize(client)
        @client = client
      end

      def tf
        apply_template(@client, "tf/iam_role2")
      end

      def tfstate
        iam_roles.inject({}) do |resources, role|
          attributes = {
            "arn" => role.arn,
            "assume_role_policy" =>
              prettify_policy(role.assume_role_policy_document, breakline: true, unescape: true),
            "id" => role.role_name,
            "name" => role.role_name,
            "path" => role.path,
            "unique_id" => role.role_id,
          }
          resources["aws_iam_role.#{module_name_of(role)}"] = {
            "type" => "aws_iam_role",
            "primary" => {
              "id" => role.role_name,
              "attributes" => attributes
            }
          }

          resources
        end
      end

      private

      # for iam_role
      def iam_roles
        @client.list_roles.map(&:roles).flatten
      end

      def module_name_of(role)
        normalize_module_name(role.role_name)
      end

      # for iam_role_policy
      def iam_role_policy_names_in(role)
        @client.list_role_policies(role_name: role.role_name).policy_names
      end

      def iam_role_policy_of(role, policy_name)
        @client.get_role_policy(role_name: role.role_name, policy_name: policy_name)
      end

      def iam_role_policies(role)
        iam_role_policy_names_in(role).map { |policy_name| iam_role_policy_of(role, policy_name) }
      end

      def unique_name(policy)
        "#{normalize_module_name(policy.role_name)}_#{normalize_module_name(policy.policy_name)}"
      end

      # for iam_role_policy_attachment
      def iam_policy_attachments_of(role)
        @client.list_attached_role_policies(role_name: role.role_name).attached_policies
      end

      def attachment_name_of(policy)
        "#{policy.policy_name}-policy-attachment"
      end

      # same as Terraforming::Resource::IAMPolicy.module_name_of
      def policy_name_of(policy)
        normalize_module_name(policy.policy_name)
      end
    end
  end
end
