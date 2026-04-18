#pragma once
#include "AccessControl.h"
#include <mutex>
#include <shared_mutex>

namespace Aegis {

// ─── ThreadSafeAccessControl ──────────────────────────────────────────────────
// A thread-safe wrapper around AccessControl using shared_mutex.
// Read operations use shared locks; write operations use exclusive locks.

class ThreadSafeAccessControl {
public:
    // ── Write operations (exclusive lock) ──

    Role& createRole(const std::string& name, const std::string& desc = "") {
        std::unique_lock lock(m_mutex);
        return m_acl.createRole(name, desc);
    }

    User& createUser(const std::string& username, const std::string& email) {
        std::unique_lock lock(m_mutex);
        return m_acl.createUser(username, email);
    }

    void assignRole(int userId, const std::string& roleName) {
        std::unique_lock lock(m_mutex);
        m_acl.assignRole(userId, roleName);
    }

    void revokeRole(int userId, const std::string& roleName) {
        std::unique_lock lock(m_mutex);
        m_acl.revokeRole(userId, roleName);
    }

    bool removeUser(int id) {
        std::unique_lock lock(m_mutex);
        return m_acl.removeUser(id);
    }

    bool removeRole(const std::string& name) {
        std::unique_lock lock(m_mutex);
        return m_acl.removeRole(name);
    }

    Resource& createResource(const std::string& type, const std::string& id) {
        std::unique_lock lock(m_mutex);
        return m_acl.createResource(type, id);
    }

    void addPolicy(Policy policy) {
        std::unique_lock lock(m_mutex);
        m_acl.addPolicy(std::move(policy));
    }

    // ── Read operations (shared lock) ──

    bool hasPermission(int userId, Permission perm) const {
        std::shared_lock lock(m_mutex);
        return m_acl.hasPermission(userId, perm);
    }

    bool hasRole(int userId, const std::string& roleName) const {
        std::shared_lock lock(m_mutex);
        return m_acl.hasRole(userId, roleName);
    }

    bool hasAllPermissions(int userId, const std::vector<Permission>& perms) const {
        std::shared_lock lock(m_mutex);
        return m_acl.hasAllPermissions(userId, perms);
    }

    bool hasAnyPermission(int userId, const std::vector<Permission>& perms) const {
        std::shared_lock lock(m_mutex);
        return m_acl.hasAnyPermission(userId, perms);
    }

    bool hasPermissionOnResource(int userId, Permission perm,
                                  const std::string& resType, const std::string& resId) const {
        std::shared_lock lock(m_mutex);
        return m_acl.hasPermissionOnResource(userId, perm, resType, resId);
    }

    bool checkAccess(int userId, Permission perm,
                     const Resource* resource = nullptr,
                     const std::unordered_map<std::string, std::string>& env = {}) const {
        std::shared_lock lock(m_mutex);
        return m_acl.checkAccess(userId, perm, resource, env);
    }

    std::unordered_set<Permission> getEffectivePermissions(int userId) const {
        std::shared_lock lock(m_mutex);
        return m_acl.getEffectivePermissions(userId);
    }

    // ── Direct access (use carefully) ──

    AccessControl& unsafe() { return m_acl; }
    const AccessControl& unsafe() const { return m_acl; }

private:
    AccessControl m_acl;
    mutable std::shared_mutex m_mutex;
};

} // namespace Aegis
