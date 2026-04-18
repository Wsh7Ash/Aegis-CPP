# Aegis-CPP

A comprehensive, header-only C++17 Access Control Library supporting RBAC, ABAC, resource-scoped permissions, and more.

## Features

| Feature | Description |
|---|---|
| **RBAC** | Role-Based Access Control with 9 enum permissions and 6 predefined roles |
| **Role Inheritance** | Roles inherit all permissions from parent roles |
| **Deny Rules** | Explicit denials that override grants (`denyPermission`) |
| **Multi-Role Users** | Users can hold multiple roles simultaneously |
| **Resource Permissions** | Scope permissions to specific resources (e.g., "post #42") with per-user and per-role overrides |
| **Ownership** | Resources can have an owner; policies can enforce owner-only access |
| **Wildcard Permissions** | Dynamic string permissions with `*` and `?` glob matching (e.g., `api:v1:posts:*`) |
| **ABAC Policies** | Attribute-Based Access Control with lambda conditions |
| **Built-in Policies** | `timeBased`, `ownerOnly`, `requireAttribute`, `denyIP`, `activeOnly` |
| **Audit Log** | Full audit trail with timestamps, filtering by user/action, real-time callbacks |
| **JSON Export** | Serialize ACL config and audit logs to JSON (no external dependencies) |
| **Thread Safety** | `ThreadSafeAccessControl` wrapper using `shared_mutex` |
| **User Attributes** | Key-value metadata on users for ABAC policy evaluation |
| **Header-Only** | Just `#include "Aegis.h"` — zero build dependencies |

## Project Structure

```
Aegis-CPP/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── Aegis.h                  # Umbrella header
│   └── Aegis/
│       ├── Permission.h         # Enum + wildcard string permissions
│       ├── Role.h               # Role with inheritance, deny, string perms
│       ├── User.h               # User with attributes and timestamps
│       ├── Resource.h           # Resource-scoped permissions + ownership
│       ├── Policy.h             # ABAC policy engine + built-in policies
│       ├── AuditLog.h           # Audit trail with callbacks
│       ├── AccessControl.h      # Core ACL engine
│       ├── Serializer.h         # JSON export
│       └── ThreadSafe.h         # Thread-safe wrapper
└── src/
    └── main.cpp                 # Full demo of all features
```

## Build & Run

```bash
mkdir build && cd build
cmake ..
cmake --build .
./AegisCPP        # or Debug/AegisCPP.exe on Windows
```

## Quick Example

```cpp
#include "Aegis.h"
using namespace Aegis;

int main() {
    AccessControl acl;

    // Create roles with inheritance
    auto& user = acl.createRole("user", "Basic reader");
    user.addPermission(Permission::ReadPosts);

    auto& admin = acl.createRole("admin", "Administrator");
    admin.inheritFrom(user);
    admin.addPermission(Permission::WritePosts);
    admin.addPermission(Permission::DeletePosts);

    // Deny rules
    auto& restricted = acl.createRole("restricted", "Limited admin");
    restricted.inheritFrom(admin);
    restricted.denyPermission(Permission::DeletePosts);

    // Create users with attributes
    auto& alice = acl.createUser("alice", "alice@example.com");
    alice.setAttribute("department", "engineering");
    acl.assignRole(alice.getId(), "admin");

    // Basic RBAC check
    acl.hasPermission(alice.getId(), Permission::WritePosts);  // true

    // Resource-scoped
    auto& post = acl.createResource("post", "42");
    post.setOwner(alice.getId());
    acl.hasPermissionOnResource(alice.getId(), Permission::DeletePosts, "post", "42");

    // Wildcard string permissions
    auto& apiRole = acl.createRole("api", "API access");
    apiRole.addStringPermission("api:v1:posts:*");
    acl.assignRole(alice.getId(), "api");
    acl.hasStringPermission(alice.getId(), "api:v1:posts:read");  // true

    // ABAC policy
    acl.addPolicy(Policies::requireAttribute("eng-only", "department", "engineering"));
    acl.checkAccess(alice.getId(), Permission::ManageSettings);  // true (engineering dept)

    // Audit log
    auto& log = acl.getAuditLog();
    for (auto& entry : log.getDenials()) {
        std::cout << entry.toString() << "\n";
    }

    // JSON export
    std::string json = Serializer::toJSON(acl);

    // Thread-safe wrapper
    ThreadSafeAccessControl tsAcl;
    tsAcl.createRole("viewer");
    tsAcl.hasPermission(1, Permission::ReadPosts);  // safe from any thread
}
```

## Role Hierarchy (default demo)

```
super_admin (9 perms)
  └── admin (7 perms)
        └── moderator (4 perms)
              └── editor (2 perms)
                    └── user (1 perm)
                          └── guest (0 perms)

restricted_mod — inherits moderator but DENIES DeletePosts
```

## Authorization Flow

```
checkAccess(userId, permission, resource?, environment?)
  │
  ├─ 1. Evaluate ABAC Policies (deny policies first, then allow conditions)
  │     └─ If any policy fails → DENIED
  │
  ├─ 2. Check Resource-Scoped Overrides (if resource provided)
  │     ├─ User-level deny on resource? → DENIED
  │     ├─ User-level grant on resource? → GRANTED
  │     ├─ Role-level deny on resource? → DENIED
  │     └─ Role-level grant on resource? → GRANTED
  │
  └─ 3. Fall back to Global RBAC
        ├─ Any role has explicit DENY? → DENIED
        ├─ Any role has GRANT? → GRANTED
        └─ Otherwise → DENIED
```
