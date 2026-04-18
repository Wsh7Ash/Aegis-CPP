#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <algorithm>

namespace Aegis {

// ─── Permission ────────────────────────────────────────────────────────────────

enum class Permission {
    ReadUsers,
    WriteUsers,
    DeleteUsers,
    ReadPosts,
    WritePosts,
    DeletePosts,
    ManageRoles,
    ViewAdminPanel,
    ManageSettings,
};

inline const char* permissionToString(Permission p) {
    switch (p) {
        case Permission::ReadUsers:      return "read:users";
        case Permission::WriteUsers:     return "write:users";
        case Permission::DeleteUsers:    return "delete:users";
        case Permission::ReadPosts:      return "read:posts";
        case Permission::WritePosts:     return "write:posts";
        case Permission::DeletePosts:    return "delete:posts";
        case Permission::ManageRoles:    return "manage:roles";
        case Permission::ViewAdminPanel: return "view:admin_panel";
        case Permission::ManageSettings: return "manage:settings";
    }
    return "unknown";
}

// ─── Role ──────────────────────────────────────────────────────────────────────

class Role {
public:
    explicit Role(const std::string& name) : m_name(name) {}

    const std::string& getName() const { return m_name; }

    void addPermission(Permission perm) {
        m_permissions.insert(perm);
    }

    void removePermission(Permission perm) {
        m_permissions.erase(perm);
    }

    bool hasPermission(Permission perm) const {
        return m_permissions.count(perm) > 0;
    }

    const std::unordered_set<Permission>& getPermissions() const {
        return m_permissions;
    }

    /// Inherit all permissions from a parent role
    void inheritFrom(const Role& parent) {
        for (auto p : parent.m_permissions) {
            m_permissions.insert(p);
        }
        m_parents.push_back(parent.m_name);
    }

    const std::vector<std::string>& getParents() const { return m_parents; }

private:
    std::string m_name;
    std::unordered_set<Permission> m_permissions;
    std::vector<std::string> m_parents;
};

// ─── User ──────────────────────────────────────────────────────────────────────

class User {
public:
    User(int id, const std::string& username, const std::string& email)
        : m_id(id), m_username(username), m_email(email), m_active(true) {}

    int getId() const { return m_id; }
    const std::string& getUsername() const { return m_username; }
    const std::string& getEmail() const { return m_email; }
    bool isActive() const { return m_active; }

    void setActive(bool active) { m_active = active; }

    void addRole(const std::string& roleName) {
        m_roles.insert(roleName);
    }

    void removeRole(const std::string& roleName) {
        m_roles.erase(roleName);
    }

    bool hasRole(const std::string& roleName) const {
        return m_roles.count(roleName) > 0;
    }

    const std::unordered_set<std::string>& getRoles() const {
        return m_roles;
    }

private:
    int m_id;
    std::string m_username;
    std::string m_email;
    bool m_active;
    std::unordered_set<std::string> m_roles;
};

// ─── AccessControl (core engine) ───────────────────────────────────────────────

class AccessControl {
public:
    // ── Role management ──

    Role& createRole(const std::string& name) {
        if (m_roles.count(name)) throw std::runtime_error("Role already exists: " + name);
        m_roles.emplace(name, Role(name));
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

    bool roleExists(const std::string& name) const {
        return m_roles.count(name) > 0;
    }

    std::vector<std::string> listRoles() const {
        std::vector<std::string> result;
        result.reserve(m_roles.size());
        for (auto& [name, _] : m_roles) result.push_back(name);
        return result;
    }

    // ── User management ──

    User& createUser(const std::string& username, const std::string& email) {
        int id = m_nextUserId++;
        m_users.emplace(id, User(id, username, email));
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
        for (auto& [_, user] : m_users) {
            if (user.getUsername() == username) return &user;
        }
        return nullptr;
    }

    bool removeUser(int id) {
        return m_users.erase(id) > 0;
    }

    std::vector<int> listUserIds() const {
        std::vector<int> result;
        result.reserve(m_users.size());
        for (auto& [id, _] : m_users) result.push_back(id);
        return result;
    }

    // ── Assignment ──

    void assignRole(int userId, const std::string& roleName) {
        getUser(userId).addRole(roleName);
    }

    void revokeRole(int userId, const std::string& roleName) {
        getUser(userId).removeRole(roleName);
    }

    // ── Authorization checks ──

    bool hasPermission(int userId, Permission perm) const {
        const auto& user = getUser(userId);
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName) && m_roles.at(roleName).hasPermission(perm)) {
                return true;
            }
        }
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

    /// Get all effective permissions for a user (union of all their roles).
    std::unordered_set<Permission> getEffectivePermissions(int userId) const {
        std::unordered_set<Permission> result;
        const auto& user = getUser(userId);
        for (const auto& roleName : user.getRoles()) {
            if (m_roles.count(roleName)) {
                for (auto p : m_roles.at(roleName).getPermissions()) {
                    result.insert(p);
                }
            }
        }
        return result;
    }

private:
    std::unordered_map<std::string, Role> m_roles;
    std::unordered_map<int, User> m_users;
    int m_nextUserId = 1;
};

} // namespace Aegis
