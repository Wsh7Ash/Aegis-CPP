#pragma once
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace Aegis {

class AccessControl {
public:
    void addRole(const std::string& role);
    void addPermissionToRole(const std::string& role, const std::string& permission);
    void assignRoleToUser(const std::string& userId, const std::string& role);
    
    bool hasPermission(const std::string& userId, const std::string& permission) const;

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> rolePermissions;
    std::unordered_map<std::string, std::string> userRoles;
};

} // namespace Aegis
