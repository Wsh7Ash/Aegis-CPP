#include <iostream>
#include <iomanip>
#include "Aegis.h"

using namespace Aegis;

void sep(const std::string& title) {
    std::cout << "\n\033[36m═══════════════════════════════════════════════════\033[0m\n";
    std::cout << "  \033[1m" << title << "\033[0m\n";
    std::cout << "\033[36m═══════════════════════════════════════════════════\033[0m\n";
}

void check(const std::string& label, bool result) {
    std::cout << "  " << std::left << std::setw(50) << label
              << (result ? "\033[32m✓ YES\033[0m" : "\033[31m✗ NO\033[0m") << "\n";
}

int main() {
    AccessControl acl;

    // ═══════════════════════════════════════════════════
    //  1. Role hierarchy with inheritance
    // ═══════════════════════════════════════════════════

    sep("1. Role Hierarchy with Inheritance");

    auto& guest = acl.createRole("guest", "No permissions");

    auto& user = acl.createRole("user", "Basic read access");
    user.addPermission(Permission::ReadPosts);

    auto& editor = acl.createRole("editor", "Can write content");
    editor.inheritFrom(user);
    editor.addPermission(Permission::WritePosts);

    auto& moderator = acl.createRole("moderator", "Content moderation");
    moderator.inheritFrom(editor);
    moderator.addPermission(Permission::DeletePosts);
    moderator.addPermission(Permission::ReadUsers);

    auto& admin = acl.createRole("admin", "Full user management");
    admin.inheritFrom(moderator);
    admin.addPermission(Permission::WriteUsers);
    admin.addPermission(Permission::DeleteUsers);
    admin.addPermission(Permission::ViewAdminPanel);

    auto& superAdmin = acl.createRole("super_admin", "God mode");
    superAdmin.inheritFrom(admin);
    superAdmin.addPermission(Permission::ManageRoles);
    superAdmin.addPermission(Permission::ManageSettings);
    superAdmin.setPriority(100);

    for (auto& r : acl.listRoles()) {
        std::cout << "  " << std::setw(14) << std::left << r
                  << acl.getRole(r).getPermissions().size() << " perms\n";
    }

    // ═══════════════════════════════════════════════════
    //  2. Users with attributes (ABAC)
    // ═══════════════════════════════════════════════════

    sep("2. Users with Attributes");

    auto& alice = acl.createUser("alice", "alice@example.com");
    alice.setAttribute("department", "engineering");
    alice.setAttribute("clearance", "top_secret");
    acl.assignRole(alice.getId(), "super_admin");

    auto& bob = acl.createUser("bob", "bob@example.com");
    bob.setAttribute("department", "marketing");
    acl.assignRole(bob.getId(), "admin");

    auto& carol = acl.createUser("carol", "carol@example.com");
    carol.setAttribute("department", "engineering");
    acl.assignRole(carol.getId(), "editor");

    auto& dave = acl.createUser("dave", "dave@example.com");
    acl.assignRole(dave.getId(), "guest");

    std::cout << "  alice: dept=" << alice.getAttribute("department") << "\n";
    std::cout << "  bob:   dept=" << bob.getAttribute("department") << "\n";
    std::cout << "  carol: dept=" << carol.getAttribute("department") << "\n";

    // ═══════════════════════════════════════════════════
    //  3. Deny rules (deny overrides grant)
    // ═══════════════════════════════════════════════════

    sep("3. Deny Rules");

    // Create a restricted editor that can write but NOT delete
    auto& restrictedMod = acl.createRole("restricted_mod", "Mod without delete");
    restrictedMod.inheritFrom(moderator);
    restrictedMod.denyPermission(Permission::DeletePosts);

    auto& eve = acl.createUser("eve", "eve@example.com");
    acl.assignRole(eve.getId(), "restricted_mod");

    check("eve (restricted_mod) can WritePosts?",  acl.hasPermission(eve.getId(), Permission::WritePosts));
    check("eve (restricted_mod) can DeletePosts?",  acl.hasPermission(eve.getId(), Permission::DeletePosts));
    check("eve (restricted_mod) can ReadUsers?",    acl.hasPermission(eve.getId(), Permission::ReadUsers));

    // ═══════════════════════════════════════════════════
    //  4. Resource-scoped permissions
    // ═══════════════════════════════════════════════════

    sep("4. Resource-Scoped Permissions");

    auto& post42 = acl.createResource("post", "42");
    post42.setOwner(carol.getId());
    post42.grantToUser(carol.getId(), Permission::DeletePosts);  // owner can delete their own post

    auto& secretDoc = acl.createResource("document", "secret-plan");
    secretDoc.denyToRole("admin", Permission::ReadPosts);  // admins can't read this specific doc

    check("carol can delete post:42?",
          acl.hasPermissionOnResource(carol.getId(), Permission::DeletePosts, "post", "42"));
    check("carol can delete post:99 (no override)?",
          acl.hasPermissionOnResource(carol.getId(), Permission::DeletePosts, "post", "99"));
    check("bob (admin) can read secret doc?",
          acl.hasPermissionOnResource(bob.getId(), Permission::ReadPosts, "document", "secret-plan"));

    // ═══════════════════════════════════════════════════
    //  5. String/wildcard permissions
    // ═══════════════════════════════════════════════════

    sep("5. Wildcard String Permissions");

    auto& apiRole = acl.createRole("api_user", "API access");
    apiRole.addStringPermission("api:v1:users:read");
    apiRole.addStringPermission("api:v1:posts:*");

    acl.assignRole(bob.getId(), "api_user");

    check("bob matches 'api:v1:posts:read'?",    acl.hasStringPermission(bob.getId(), "api:v1:posts:read"));
    check("bob matches 'api:v1:posts:delete'?",  acl.hasStringPermission(bob.getId(), "api:v1:posts:delete"));
    check("bob matches 'api:v1:users:read'?",    acl.hasStringPermission(bob.getId(), "api:v1:users:read"));
    check("bob matches 'api:v1:users:delete'?",  acl.hasStringPermission(bob.getId(), "api:v1:users:delete"));
    check("bob matches 'api:v2:*'?",             acl.hasStringPermission(bob.getId(), "api:v2:*"));

    // ═══════════════════════════════════════════════════
    //  6. Policy engine (ABAC)
    // ═══════════════════════════════════════════════════

    sep("6. Policy Engine (ABAC)");

    // Only active users
    acl.addPolicy(Policies::activeOnly("active-users-only"));

    // Only engineering department can manage settings
    acl.addPolicy(Policies::requireAttribute("engineering-only", "department", "engineering"));

    // Test with active user in engineering
    check("alice (engineering, active) checkAccess ManageSettings?",
          acl.checkAccess(alice.getId(), Permission::ManageSettings, nullptr,
                          {{"hour", "14"}}));

    // Test with marketing user
    check("bob (marketing) checkAccess ManageSettings?",
          acl.checkAccess(bob.getId(), Permission::ManageSettings, nullptr,
                          {{"hour", "14"}}));

    // Deactivate dave and test
    dave.setActive(false);
    check("dave (inactive guest) checkAccess ReadPosts?",
          acl.checkAccess(dave.getId(), Permission::ReadPosts));

    // ═══════════════════════════════════════════════════
    //  7. Audit log
    // ═══════════════════════════════════════════════════

    sep("7. Audit Log");

    auto& log = acl.getAuditLog();
    std::cout << "  Total audit entries: " << log.size() << "\n";
    std::cout << "  Denials: " << log.getDenials().size() << "\n\n";

    std::cout << "  Last 5 entries:\n";
    auto& entries = log.getEntries();
    size_t start = entries.size() > 5 ? entries.size() - 5 : 0;
    for (size_t i = start; i < entries.size(); ++i) {
        std::cout << "    " << entries[i].toString() << "\n";
    }

    // ═══════════════════════════════════════════════════
    //  8. JSON export
    // ═══════════════════════════════════════════════════

    sep("8. JSON Export (preview)");

    std::string json = Serializer::toJSON(acl);
    // Print first 500 chars
    std::cout << json.substr(0, 500) << "\n  ... (truncated)\n";

    // ═══════════════════════════════════════════════════
    //  9. Effective permissions
    // ═══════════════════════════════════════════════════

    sep("9. Effective Permissions for eve (restricted_mod)");

    auto evePerms = acl.getEffectivePermissions(eve.getId());
    for (auto p : evePerms) {
        std::cout << "  ✓ " << permissionToString(p) << "\n";
    }

    std::cout << "\n\033[32m══════════ All demos complete! ══════════\033[0m\n\n";
    return 0;
}
