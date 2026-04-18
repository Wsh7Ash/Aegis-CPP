#pragma once
#include "Permission.h"
#include <string>
#include <vector>
#include <unordered_set>

namespace Aegis {

// ─── Role ──────────────────────────────────────────────────────────────────────

class Role {
public:
    explicit Role(const std::string& name, const std::string& description = "")
        : m_name(name), m_description(description), m_priority(0) {}

    const std::string& getName() const { return m_name; }
    const std::string& getDescription() const { return m_description; }
    void setDescription(const std::string& desc) { m_description = desc; }

    /// Priority for conflict resolution (higher = more authoritative)
    int getPriority() const { return m_priority; }
    void setPriority(int priority) { m_priority = priority; }

    // ── Enum permissions ──

    void addPermission(Permission perm) { m_permissions.insert(perm); }
    void removePermission(Permission perm) { m_permissions.erase(perm); }
    bool hasPermission(Permission perm) const { return m_permissions.count(perm) > 0; }
    const std::unordered_set<Permission>& getPermissions() const { return m_permissions; }

    // ── Deny rules (explicit denials override grants) ──

    void denyPermission(Permission perm) { m_deniedPermissions.insert(perm); }
    void removeDeny(Permission perm) { m_deniedPermissions.erase(perm); }
    bool isDenied(Permission perm) const { return m_deniedPermissions.count(perm) > 0; }
    const std::unordered_set<Permission>& getDeniedPermissions() const { return m_deniedPermissions; }

    // ── String-based permissions ──

    void addStringPermission(const std::string& perm) { m_stringPermissions.insert(StringPermission(perm)); }
    void removeStringPermission(const std::string& perm) { m_stringPermissions.erase(StringPermission(perm)); }

    /// Check if the role grants a string permission.
    /// The stored permissions may contain wildcards (e.g., "api:v1:posts:*").
    /// The query is a concrete permission string (e.g., "api:v1:posts:read").
    bool hasStringPermission(const std::string& query) const {
        StringPermission q(query);
        for (const auto& sp : m_stringPermissions) {
            // The stored permission is the pattern, the query is the text
            if (q.matches(sp.str())) return true;
        }
        return false;
    }

    const std::unordered_set<StringPermission, StringPermissionHash>& getStringPermissions() const {
        return m_stringPermissions;
    }

    // ── Inheritance ──

    void inheritFrom(const Role& parent) {
        for (auto p : parent.m_permissions) m_permissions.insert(p);
        for (auto p : parent.m_deniedPermissions) m_deniedPermissions.insert(p);
        for (auto& sp : parent.m_stringPermissions) m_stringPermissions.insert(sp);
        m_parents.push_back(parent.m_name);
    }

    const std::vector<std::string>& getParents() const { return m_parents; }

private:
    std::string m_name;
    std::string m_description;
    int m_priority;
    std::unordered_set<Permission> m_permissions;
    std::unordered_set<Permission> m_deniedPermissions;
    std::unordered_set<StringPermission, StringPermissionHash> m_stringPermissions;
    std::vector<std::string> m_parents;
};

} // namespace Aegis
