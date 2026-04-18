#include <iostream>
#include "Aegis.h"

int main() {
    Aegis::AccessControl acl;

    // Setup roles
    acl.addRole("admin");
    acl.addRole("user");

    // Assign permissions
    acl.addPermissionToRole("admin", "delete_files");
    acl.addPermissionToRole("admin", "read_files");
    acl.addPermissionToRole("user", "read_files");

    // Register users
    acl.assignRoleToUser("alice", "admin");
    acl.assignRoleToUser("bob", "user");

    // Test access
    std::cout << "Alice can delete: " << (acl.hasPermission("alice", "delete_files") ? "Yes" : "No") << "\n";
    std::cout << "Bob can delete: " << (acl.hasPermission("bob", "delete_files") ? "Yes" : "No") << "\n";

    return 0;
}
