#pragma once
#include "Permission.h"
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace Aegis {

// ─── Resource ──────────────────────────────────────────────────────────────────
// Represents a specific resource (e.g., "post #42", "file /docs/secret.pdf")
// that can have its own permission overrides per user or role.

class Resource {
public:
    Resource(const std::string& type, const std::string& id)
        : m_type(type), m_id(id) {}

    const std::string& getType() const { return m_type; }
    const std::string& getId() const { return m_id; }
    std::string getKey() const { return m_type + ":" + m_id; }

    // ── Owner ──

    void setOwner(int userId) { m_ownerId = userId; m_hasOwner = true; }
    int getOwner() const { return m_ownerId; }
    bool hasOwner() const { return m_hasOwner; }
    bool isOwner(int userId) const { return m_hasOwner && m_ownerId == userId; }

    // ── Per-user permission overrides on this resource ──

    void grantToUser(int userId, Permission perm) {
        m_userGrants[userId].insert(perm);
    }

    void denyToUser(int userId, Permission perm) {
        m_userDenials[userId].insert(perm);
    }

    void revokeFromUser(int userId, Permission perm) {
        if (m_userGrants.count(userId)) m_userGrants[userId].erase(perm);
        if (m_userDenials.count(userId)) m_userDenials[userId].erase(perm);
    }

    bool isGrantedToUser(int userId, Permission perm) const {
        auto it = m_userGrants.find(userId);
        return it != m_userGrants.end() && it->second.count(perm) > 0;
    }

    bool isDeniedToUser(int userId, Permission perm) const {
        auto it = m_userDenials.find(userId);
        return it != m_userDenials.end() && it->second.count(perm) > 0;
    }

    // ── Per-role permission overrides on this resource ──

    void grantToRole(const std::string& role, Permission perm) {
        m_roleGrants[role].insert(perm);
    }

    void denyToRole(const std::string& role, Permission perm) {
        m_roleDenials[role].insert(perm);
    }

    bool isGrantedToRole(const std::string& role, Permission perm) const {
        auto it = m_roleGrants.find(role);
        return it != m_roleGrants.end() && it->second.count(perm) > 0;
    }

    bool isDeniedToRole(const std::string& role, Permission perm) const {
        auto it = m_roleDenials.find(role);
        return it != m_roleDenials.end() && it->second.count(perm) > 0;
    }

    // ── Metadata ──

    void setMeta(const std::string& key, const std::string& value) { m_meta[key] = value; }
    std::string getMeta(const std::string& key, const std::string& def = "") const {
        auto it = m_meta.find(key);
        return it != m_meta.end() ? it->second : def;
    }

private:
    std::string m_type;
    std::string m_id;
    int m_ownerId = -1;
    bool m_hasOwner = false;

    std::unordered_map<int, std::unordered_set<Permission>> m_userGrants;
    std::unordered_map<int, std::unordered_set<Permission>> m_userDenials;
    std::unordered_map<std::string, std::unordered_set<Permission>> m_roleGrants;
    std::unordered_map<std::string, std::unordered_set<Permission>> m_roleDenials;
    std::unordered_map<std::string, std::string> m_meta;
};

} // namespace Aegis
