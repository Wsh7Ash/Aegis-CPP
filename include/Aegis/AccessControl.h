#pragma once
#include "Permission.h"
#include "Role.h"
#include "User.h"
#include "Resource.h"
#include "Policy.h"
#include "AuditLog.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>

namespace Aegis {

class AccessControl {
public:
    AccessControl() : m_auditEnabled(true) {}

    // ── Audit ──
    AuditLog& getAuditLog() { return m_auditLog; }
    void setAuditEnabled(bool e) { m_auditEnabled = e; }

    // ── Role management ──

    Role& createRole(const std::string& name, const std::string& desc = "") {
        if (m_roles.count(name)) throw std::runtime_error("Role exists: " + name);
        m_roles.emplace(name, Role(name, desc));
        return m_roles.at(name);
    }

    Role& getRole(const std::string& name) {
        auto it = m_roles.find(name);
        if (it == m_roles.end()) throw std::runtime_error("Role not found: " + name);
        return it->second;
    }

    const Role& getRole(const std::string& name) const {
        auto it = m_roles.find(name);
        if (it == m_roles.end()) throw std::runtime_error("Role not found: " + name);
        return it->second;
    }

    bool roleExists(const std::string& n) const { return m_roles.count(n) > 0; }

    std::vector<std::string> listRoles() const {
        std::vector<std::string> r;
        for (auto& [n, _] : m_roles) r.push_back(n);
        return r;
    }

    bool removeRole(const std::string& name) { return m_roles.erase(name) > 0; }

    // ── User management ──

    User& createUser(const std::string& username, const std::string& email) {
        int id = m_nextUserId++;
        m_users.emplace(id, User(id, username, email));
        if (m_auditEnabled) m_auditLog.log(AuditAction::UserCreated, id, "created: " + username, true);
        return m_users.at(id);
    }

    User& getUser(int id) {
        auto it = m_users.find(id);
        if (it == m_users.end()) throw std::runtime_error("User not found");
        return it->second;
    }

    const User& getUser(int id) const {
        auto it = m_users.find(id);
        if (it == m_users.end()) throw std::runtime_error("User not found");
        return it->second;
    }

    User* findUserByUsername(const std::string& username) {
        for (auto& [_, u] : m_users) if (u.getUsername() == username) return &u;
        return nullptr;
    }

    bool removeUser(int id) {
        if (m_auditEnabled) m_auditLog.log(AuditAction::UserDeleted, id, "deleted", m_users.count(id));
        return m_users.erase(id) > 0;
    }

    std::vector<int> listUserIds() const {
        std::vector<int> r;
        for (auto& [id, _] : m_users) r.push_back(id);
        return r;
    }

    // ── Role assignment ──

    void assignRole(int userId, const std::string& roleName) {
        getUser(userId).addRole(roleName);
        if (m_auditEnabled) m_auditLog.log(AuditAction::RoleAssigned, userId, "role=" + roleName, true);
    }

    void revokeRole(int userId, const std::string& roleName) {
        getUser(userId).removeRole(roleName);
        if (m_auditEnabled) m_auditLog.log(AuditAction::RoleRevoked, userId, "role=" + roleName, true);
    }

    // ── Resource management ──

    Resource& createResource(const std::string& type, const std::string& id) {
        std::string key = type + ":" + id;
        m_resources.emplace(key, Resource(type, id));
        return m_resources.at(key);
    }

    Resource& getResource(const std::string& type, const std::string& id) {
        std::string key = type + ":" + id;
        auto it = m_resources.find(key);
        if (it == m_resources.end()) throw std::runtime_error("Resource not found: " + key);
        return it->second;
    }

    bool resourceExists(const std::string& type, const std::string& id) const {
        return m_resources.count(type + ":" + id) > 0;
    }

    // ── Policy management ──

    void addPolicy(Policy policy) {
        m_policies.push_back(std::move(policy));
    }

    std::vector<Policy>& getPolicies() { return m_policies; }

    // ── Authorization: basic RBAC ──

    bool hasPermission(int userId, Permission perm) const {
        const auto& user = getUser(userId);
        if (!user.isActive()) {
            audit(AuditAction::PermissionCheck, userId, permissionToString(perm), false);
            return false;
        }

        // Check deny rules first (deny overrides grant)
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName) && m_roles.at(roleName).isDenied(perm)) {
                audit(AuditAction::PermissionCheck, userId,
                      std::string(permissionToString(perm)) + " DENIED by role=" + roleName, false);
                return false;
            }
        }

        // Check grants
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName) && m_roles.at(roleName).hasPermission(perm)) {
                audit(AuditAction::PermissionCheck, userId, permissionToString(perm), true);
                return true;
            }
        }

        audit(AuditAction::PermissionCheck, userId, permissionToString(perm), false);
        return false;
    }

    bool hasRole(int userId, const std::string& roleName) const {
        return getUser(userId).hasRole(roleName);
    }

    bool hasAllPermissions(int userId, const std::vector<Permission>& perms) const {
        return std::all_of(perms.begin(), perms.end(), [&](Permission p) {
            return hasPermission(userId, p);
        });
    }

    bool hasAnyPermission(int userId, const std::vector<Permission>& perms) const {
        return std::any_of(perms.begin(), perms.end(), [&](Permission p) {
            return hasPermission(userId, p);
        });
    }

    std::unordered_set<Permission> getEffectivePermissions(int userId) const {
        std::unordered_set<Permission> result;
        const auto& user = getUser(userId);
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName)) {
                for (auto p : m_roles.at(roleName).getPermissions()) {
                    if (!isDeniedForUser(userId, p)) result.insert(p);
                }
            }
        }
        return result;
    }

    // ── Authorization: resource-scoped ──

    bool hasPermissionOnResource(int userId, Permission perm,
                                 const std::string& resType, const std::string& resId) const {
        std::string key = resType + ":" + resId;
        auto resIt = m_resources.find(key);
        const auto& user = getUser(userId);

        if (resIt != m_resources.end()) {
            const auto& res = resIt->second;
            // Explicit user denial on resource
            if (res.isDeniedToUser(userId, perm)) {
                audit(AuditAction::ResourceAccess, userId, key + " " + permissionToString(perm), false);
                return false;
            }
            // Explicit user grant on resource
            if (res.isGrantedToUser(userId, perm)) {
                audit(AuditAction::ResourceAccess, userId, key + " " + permissionToString(perm), true);
                return true;
            }
            // Role-level grants/denials on resource
            for (const auto& roleName : user.getRoles()) {
                if (res.isDeniedToRole(roleName, perm)) {
                    audit(AuditAction::ResourceAccess, userId, key + " " + permissionToString(perm), false);
                    return false;
                }
                if (res.isGrantedToRole(roleName, perm)) {
                    audit(AuditAction::ResourceAccess, userId, key + " " + permissionToString(perm), true);
                    return true;
                }
            }
        }
        // Fall back to global RBAC
        return hasPermission(userId, perm);
    }

    // ── Authorization: with policies (ABAC) ──

    bool checkAccess(int userId, Permission perm,
                     const Resource* resource = nullptr,
                     const std::unordered_map<std::string, std::string>& env = {}) const {
        const auto& user = getUser(userId);

        // Build policy context
        PolicyContext ctx;
        ctx.user = &user;
        ctx.resource = resource;
        ctx.permission = perm;
        ctx.environment = env;

        // Evaluate all policies
        for (const auto& policy : m_policies) {
            bool passed = policy.evaluate(ctx);
            if (policy.getEffect() == PolicyEffect::Deny && passed) {
                audit(AuditAction::PolicyEvaluated, userId,
                      "policy=" + policy.getName() + " DENY triggered", false);
                return false;
            }
            if (policy.getEffect() == PolicyEffect::Allow && !passed) {
                audit(AuditAction::PolicyEvaluated, userId,
                      "policy=" + policy.getName() + " ALLOW failed", false);
                return false;
            }
        }

        // If resource provided, check resource-scoped permissions
        if (resource) {
            return hasPermissionOnResource(userId, perm, resource->getType(), resource->getId());
        }
        return hasPermission(userId, perm);
    }

    // ── String permission checks ──

    bool hasStringPermission(int userId, const std::string& pattern) const {
        const auto& user = getUser(userId);
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName) && m_roles.at(roleName).hasStringPermission(pattern)) {
                return true;
            }
        }
        return false;
    }

private:
    std::unordered_map<std::string, Role> m_roles;
    std::unordered_map<int, User> m_users;
    std::unordered_map<std::string, Resource> m_resources;
    std::vector<Policy> m_policies;
    mutable AuditLog m_auditLog;
    bool m_auditEnabled;
    int m_nextUserId = 1;

    bool isDeniedForUser(int userId, Permission perm) const {
        const auto& user = getUser(userId);
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName) && m_roles.at(roleName).isDenied(perm)) return true;
        }
        return false;
    }

    void audit(AuditAction action, int userId, const std::string& detail, bool result) const {
        if (m_auditEnabled) m_auditLog.log(action, userId, detail, result);
    }
};

} // namespace Aegis
