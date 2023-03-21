module Himari
  class RuleProcessor
    class MissingDecisionError < StandardError; end

    Result = Struct.new(:rule_name, :allowed, :explicit_deny, :decision, :decision_log, :user_facing_message, :suggestion, keyword_init: true) do
      def as_log
        {
          rule_name: rule_name,
          allowed: allowed,
          explicit_deny: explicit_deny,
          decision: decision&.as_log,
          decision_log: decision_log.map(&:to_h),
        }.tap do |x|
          x[:suggestion] = suggestion if suggestion
        end
      end
    end

    # @param context [Object] Context data
    # @param initial_decision [Himari::Decisions::Base] Initial decision
    def initialize(context, initial_decision)
      @context = context
      @initial_decision = initial_decision

      @result = Result.new(rule_name: nil, allowed: false, explicit_deny: false, decision: nil, decision_log: [])
      @decision = initial_decision
      @final = false
    end

    attr_reader :rules, :context, :initial_decision
    attr_reader :result

    def final?; @final; end

    # @param rules [Himari::Rule] rules
    def process(rule)
      raise "cannot process rule for finalized result [BUG]" if final?

      decision = @decision.evolve(rule.name)

      rule.call(context, decision)
      raise MissingDecisionError, "rule '#{rule.name}' returned no decision; rule must use one of decision.allow!, deny!, continue!, skip!" unless decision.effect
      result.decision_log.push(decision)

      case decision.effect
      when :allow
        @decision = decision
        result.rule_name ||= rule.name
        result.decision = decision
        result.allowed = true
        result.explicit_deny = false
        result.user_facing_message = decision.effect_user_facing_message

      when :continue
        @decision = decision
        result.decision = decision

      when :skip
        # do nothing

      when :deny
        @final = true
        result.rule_name = rule.name
        result.decision = nil
        result.allowed = false
        result.explicit_deny = true
        result.user_facing_message = decision.effect_user_facing_message
        result.suggestion = decision.effect_suggestion

      else
        raise "Unknown effect #{decision.effect} [BUG]"
      end
    end

    # @param rules [Array<Himari::Rule>] rules
    def run(rules)
      rules.each do |rule|
        process(rule)
        break if final?
      end
      @final = true
      result.decision ||= @initial_decision unless result.explicit_deny
      result
    end
  end
end
