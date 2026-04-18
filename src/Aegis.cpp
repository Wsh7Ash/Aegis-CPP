#include "Aegis.h"

namespace Aegis {

void AccessControl::addRole(const std::string& role) {
    if (rolePermissions.find(role) == rolePermissions.end()) {
        rolePermissions[role] = std::unordered_set<std::string>();
    }
}

void AccessControl::addPermissionToRole(const std::string& role, const std::string& permission) {
    rolePermissions[role].insert(permission);
}

void AccessControl::assignRoleToUser(const std::string& userId, const std::string& role) {
    userRoles[userId] = role;
}

bool AccessControl::hasPermission(const std::string& userId, const std::string& permission) const {
    auto userRoleIt = userRoles.find(userId);
    if (userRoleIt == userRoles.end()) {
        return false;
    }
    
    const std::string& role = userRoleIt->second;
    auto rolePermIt = rolePermissions.find(role);
    if (rolePermIt == rolePermissions.end()) {
        return false;
    }
    
    return rolePermIt->second.find(permission) != rolePermIt->second.end();
}

} // namespace Aegis
