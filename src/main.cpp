#include <iostream>
#include <iomanip>
#include "Aegis.h"

using namespace Aegis;

void printSeparator(const std::string& title) {
    std::cout << "\n═══════════════════════════════════════════════════\n";
    std::cout << "  " << title << "\n";
    std::cout << "═══════════════════════════════════════════════════\n";
}

void printCheck(const std::string& label, bool result) {
    std::cout << "  " << std::left << std::setw(45) << label
              << (result ? "✓ YES" : "✗ NO") << "\n";
}

int main() {
    AccessControl acl;

    // ─── 1. Create roles with permission inheritance ───────────────────

    printSeparator("Setting up roles");

    auto& guest = acl.createRole("guest");
    // guests have no permissions

    auto& user = acl.createRole("user");
    user.addPermission(Permission::ReadPosts);

    auto& editor = acl.createRole("editor");
    editor.inheritFrom(user);
    editor.addPermission(Permission::WritePosts);

    auto& moderator = acl.createRole("moderator");
    moderator.inheritFrom(editor);
    moderator.addPermission(Permission::DeletePosts);
    moderator.addPermission(Permission::ReadUsers);

    auto& admin = acl.createRole("admin");
    admin.inheritFrom(moderator);
    admin.addPermission(Permission::WriteUsers);
    admin.addPermission(Permission::DeleteUsers);
    admin.addPermission(Permission::ViewAdminPanel);

    auto& superAdmin = acl.createRole("super_admin");
    superAdmin.inheritFrom(admin);
    superAdmin.addPermission(Permission::ManageRoles);
    superAdmin.addPermission(Permission::ManageSettings);

    std::cout << "  Created " << acl.listRoles().size() << " roles:\n";
    for (const auto& r : acl.listRoles()) {
        std::cout << "    - " << r << " (" << acl.getRole(r).getPermissions().size() << " permissions)\n";
    }

    // ─── 2. Create users ──────────────────────────────────────────────

    printSeparator("Registering users");

    auto& alice = acl.createUser("alice", "alice@example.com");
    acl.assignRole(alice.getId(), "super_admin");
    std::cout << "  alice  → super_admin\n";

    auto& bob = acl.createUser("bob", "bob@example.com");
    acl.assignRole(bob.getId(), "admin");
    std::cout << "  bob    → admin\n";

    auto& carol = acl.createUser("carol", "carol@example.com");
    acl.assignRole(carol.getId(), "moderator");
    std::cout << "  carol  → moderator\n";

    auto& dave = acl.createUser("dave", "dave@example.com");
    acl.assignRole(dave.getId(), "editor");
    std::cout << "  dave   → editor\n";

    auto& eve = acl.createUser("eve", "eve@example.com");
    acl.assignRole(eve.getId(), "user");
    std::cout << "  eve    → user\n";

    auto& frank = acl.createUser("frank", "frank@example.com");
    acl.assignRole(frank.getId(), "guest");
    std::cout << "  frank  → guest\n";

    // ─── 3. Permission checks ─────────────────────────────────────────

    printSeparator("Permission checks");

    printCheck("alice (super_admin) can ManageSettings?", acl.hasPermission(alice.getId(), Permission::ManageSettings));
    printCheck("alice (super_admin) can DeletePosts?",    acl.hasPermission(alice.getId(), Permission::DeletePosts));
    printCheck("bob (admin) can ViewAdminPanel?",         acl.hasPermission(bob.getId(), Permission::ViewAdminPanel));
    printCheck("bob (admin) can ManageSettings?",         acl.hasPermission(bob.getId(), Permission::ManageSettings));
    printCheck("carol (moderator) can DeletePosts?",      acl.hasPermission(carol.getId(), Permission::DeletePosts));
    printCheck("carol (moderator) can DeleteUsers?",      acl.hasPermission(carol.getId(), Permission::DeleteUsers));
    printCheck("dave (editor) can WritePosts?",           acl.hasPermission(dave.getId(), Permission::WritePosts));
    printCheck("dave (editor) can DeletePosts?",          acl.hasPermission(dave.getId(), Permission::DeletePosts));
    printCheck("eve (user) can ReadPosts?",               acl.hasPermission(eve.getId(), Permission::ReadPosts));
    printCheck("eve (user) can WritePosts?",              acl.hasPermission(eve.getId(), Permission::WritePosts));
    printCheck("frank (guest) can ReadPosts?",            acl.hasPermission(frank.getId(), Permission::ReadPosts));

    // ─── 4. Multi-role assignment ─────────────────────────────────────

    printSeparator("Multi-role demo");

    acl.assignRole(eve.getId(), "editor");
    std::cout << "  Assigned 'editor' to eve (now has: user + editor)\n";
    printCheck("eve can now WritePosts?", acl.hasPermission(eve.getId(), Permission::WritePosts));

    // ─── 5. Effective permissions ─────────────────────────────────────

    printSeparator("Eve's effective permissions");
    auto evePerms = acl.getEffectivePermissions(eve.getId());
    for (auto p : evePerms) {
        std::cout << "  - " << permissionToString(p) << "\n";
    }

    // ─── 6. hasAll / hasAny ───────────────────────────────────────────

    printSeparator("Bulk permission checks");

    printCheck("bob has ALL [ReadUsers, WriteUsers]?",
        acl.hasAllPermissions(bob.getId(), {Permission::ReadUsers, Permission::WriteUsers}));
    printCheck("bob has ALL [ReadUsers, ManageSettings]?",
        acl.hasAllPermissions(bob.getId(), {Permission::ReadUsers, Permission::ManageSettings}));
    printCheck("dave has ANY [ManageRoles, WritePosts]?",
        acl.hasAnyPermission(dave.getId(), {Permission::ManageRoles, Permission::WritePosts}));

    // ─── 7. Deactivation ─────────────────────────────────────────────

    printSeparator("User deactivation");

    frank.setActive(false);
    std::cout << "  frank is active? " << (frank.isActive() ? "Yes" : "No") << "\n";

    std::cout << "\n══════════ Done ══════════\n";
    return 0;
}
