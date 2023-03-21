module Himari
  module Decisions
    class Base
      class DecisionAlreadyMade < StandardError; end
      class InvalidEffect < StandardError; end

      def self.allow_effects(*effects)
        @valid_effects = effects
      end

      def self.valid_effects
        @valid_effects
      end

      def initialize
        @rule_name = nil
        @effect = nil
        raise "#{self.class.name}.valid_effects is missing [BUG]" unless self.class.valid_effects
      end

      attr_reader :effect, :effect_comment, :effect_user_facing_message, :rule_name

      def to_evolve_args
        raise NotImplementedError
      end

      def to_h
        {
          rule_name: rule_name,
          effect: effect,
          effect_comment: effect_comment,
        }.tap do |x|
          x[:effect_user_facing_message] = effect_user_facing_message if effect_user_facing_message
        end
      end

      def as_log
        to_h
      end

      def evolve(rule_name)
        self.class.new(**to_evolve_args).set_rule_name(rule_name)
      end

      def set_rule_name(rule_name)
        raise "cannot override rule_name" if @rule_name
        @rule_name = rule_name
        self
      end

      def decide!(effect, comment = "", user_facing_message: nil)
        raise DecisionAlreadyMade, "decision can only be made once per rule (#{rule_name})" if @effect
        raise InvalidEffect, "this effect is not valid under this rule. Valid effects: #{self.class.valid_effects.inspect} (#{rule_name})" unless self.class.valid_effects.include?(effect)
        @effect = effect
        @effect_comment = comment
        @effect_user_facing_message = user_facing_message
        nil
      end

      def allow!(*args, **kwargs); decide!(:allow, *args, **kwargs); end
      def continue!(*args, **kwargs); decide!(:continue, *args, **kwargs); end
      def deny!(*args, **kwargs); decide!(:deny, *args, **kwargs); end
      def skip!(*args, **kwargs); decide!(:skip, *args, **kwargs); end
    end
  end
end
