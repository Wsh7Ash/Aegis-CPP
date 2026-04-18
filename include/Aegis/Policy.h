#pragma once
#include "Permission.h"
#include "User.h"
#include "Resource.h"
#include <string>
#include <vector>
#include <functional>

namespace Aegis {

// ─── Policy (ABAC condition engine) ────────────────────────────────────────────
// Policies are named conditions that must be satisfied for access to be granted.
// They enable Attribute-Based Access Control on top of RBAC.

struct PolicyContext {
    const User* user = nullptr;
    const Resource* resource = nullptr;
    Permission permission;
    std::unordered_map<std::string, std::string> environment;  // e.g., "ip", "time"
};

using PolicyFunc = std::function<bool(const PolicyContext&)>;

enum class PolicyEffect {
    Allow,
    Deny,
};

class Policy {
public:
    Policy(const std::string& name, PolicyEffect effect, PolicyFunc condition)
        : m_name(name), m_effect(effect), m_condition(std::move(condition)), m_enabled(true) {}

    const std::string& getName() const { return m_name; }
    PolicyEffect getEffect() const { return m_effect; }
    bool isEnabled() const { return m_enabled; }
    void setEnabled(bool enabled) { m_enabled = enabled; }

    /// Evaluate this policy against the given context.
    bool evaluate(const PolicyContext& ctx) const {
        if (!m_enabled) return true;  // disabled policies don't block
        return m_condition(ctx);
    }

private:
    std::string m_name;
    PolicyEffect m_effect;
    PolicyFunc m_condition;
    bool m_enabled;
};

// ─── Built-in policy factories ─────────────────────────────────────────────────

namespace Policies {

    /// Only allow access during specific hours (24h format, inclusive).
    inline Policy timeBased(const std::string& name, int startHour, int endHour) {
        return Policy(name, PolicyEffect::Allow, [startHour, endHour](const PolicyContext& ctx) {
            auto hourStr = ctx.environment.find("hour");
            if (hourStr == ctx.environment.end()) return true; // no hour info = allow
            int hour = std::stoi(hourStr->second);
            if (startHour <= endHour) {
                return hour >= startHour && hour <= endHour;
            } else {
                // Wrap-around (e.g., 22 to 6)
                return hour >= startHour || hour <= endHour;
            }
        });
    }

    /// Only allow if user has a specific attribute value.
    inline Policy requireAttribute(const std::string& name, const std::string& key, const std::string& value) {
        return Policy(name, PolicyEffect::Allow, [key, value](const PolicyContext& ctx) {
            if (!ctx.user) return false;
            return ctx.user->getAttribute(key) == value;
        });
    }

    /// Only allow the resource owner.
    inline Policy ownerOnly(const std::string& name) {
        return Policy(name, PolicyEffect::Allow, [](const PolicyContext& ctx) {
            if (!ctx.user || !ctx.resource) return false;
            return ctx.resource->isOwner(ctx.user->getId());
        });
    }

    /// Deny access from a specific IP or IP range (simple string match).
    inline Policy denyIP(const std::string& name, const std::string& blockedIP) {
        return Policy(name, PolicyEffect::Deny, [blockedIP](const PolicyContext& ctx) {
            auto ip = ctx.environment.find("ip");
            if (ip == ctx.environment.end()) return false; // no IP = don't deny
            return ip->second == blockedIP;
        });
    }

    /// Only allow if user account is active.
    inline Policy activeOnly(const std::string& name) {
        return Policy(name, PolicyEffect::Allow, [](const PolicyContext& ctx) {
            if (!ctx.user) return false;
            return ctx.user->isActive();
        });
    }

    /// Custom policy with a lambda.
    inline Policy custom(const std::string& name, PolicyEffect effect, PolicyFunc func) {
        return Policy(name, effect, std::move(func));
    }

} // namespace Policies

} // namespace Aegis
