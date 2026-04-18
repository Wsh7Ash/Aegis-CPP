#pragma once
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <chrono>

namespace Aegis {

// ─── User ──────────────────────────────────────────────────────────────────────

class User {
public:
    User(int id, const std::string& username, const std::string& email)
        : m_id(id), m_username(username), m_email(email), m_active(true) {
        m_createdAt = std::chrono::system_clock::now();
    }

    int getId() const { return m_id; }
    const std::string& getUsername() const { return m_username; }
    const std::string& getEmail() const { return m_email; }
    bool isActive() const { return m_active; }
    void setActive(bool active) { m_active = active; }

    // ── Roles ──

    void addRole(const std::string& roleName) { m_roles.insert(roleName); }
    void removeRole(const std::string& roleName) { m_roles.erase(roleName); }
    bool hasRole(const std::string& roleName) const { return m_roles.count(roleName) > 0; }
    const std::unordered_set<std::string>& getRoles() const { return m_roles; }
    void clearRoles() { m_roles.clear(); }

    // ── Metadata / Attributes (for ABAC policies) ──

    void setAttribute(const std::string& key, const std::string& value) { m_attributes[key] = value; }
    std::string getAttribute(const std::string& key, const std::string& defaultVal = "") const {
        auto it = m_attributes.find(key);
        return it != m_attributes.end() ? it->second : defaultVal;
    }
    bool hasAttribute(const std::string& key) const { return m_attributes.count(key) > 0; }
    const std::unordered_map<std::string, std::string>& getAttributes() const { return m_attributes; }

    // ── Timestamps ──

    std::chrono::system_clock::time_point getCreatedAt() const { return m_createdAt; }

private:
    int m_id;
    std::string m_username;
    std::string m_email;
    bool m_active;
    std::unordered_set<std::string> m_roles;
    std::unordered_map<std::string, std::string> m_attributes;
    std::chrono::system_clock::time_point m_createdAt;
};

} // namespace Aegis
