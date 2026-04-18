#pragma once
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <functional>

namespace Aegis {

// ─── Enum-based Permissions ────────────────────────────────────────────────────

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

    // Extensible: add your own above this line
    _Count
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
        default:                         return "unknown";
    }
}

// ─── String-based (dynamic) Permissions ────────────────────────────────────────
// For runtime-defined permissions like "posts:42:edit" or "files:*/read"

class StringPermission {
public:
    explicit StringPermission(const std::string& perm) : m_permission(perm) {}

    const std::string& str() const { return m_permission; }

    /// Match against a pattern with wildcard support.
    /// e.g., "posts:42:edit" matches pattern "posts:*:edit"
    bool matches(const std::string& pattern) const {
        return matchWildcard(pattern, m_permission);
    }

    bool operator==(const StringPermission& other) const { return m_permission == other.m_permission; }
    bool operator!=(const StringPermission& other) const { return m_permission != other.m_permission; }

private:
    std::string m_permission;

    static bool matchWildcard(const std::string& pattern, const std::string& text) {
        size_t pi = 0, ti = 0;
        size_t starP = std::string::npos, starT = 0;

        while (ti < text.size()) {
            if (pi < pattern.size() && (pattern[pi] == text[ti] || pattern[pi] == '?')) {
                ++pi; ++ti;
            } else if (pi < pattern.size() && pattern[pi] == '*') {
                starP = pi++;
                starT = ti;
            } else if (starP != std::string::npos) {
                pi = starP + 1;
                ti = ++starT;
            } else {
                return false;
            }
        }
        while (pi < pattern.size() && pattern[pi] == '*') ++pi;
        return pi == pattern.size();
    }
};

struct StringPermissionHash {
    size_t operator()(const StringPermission& sp) const {
        return std::hash<std::string>{}(sp.str());
    }
};

} // namespace Aegis
