# Aegis-CPP

A lightweight, header-only C++17 Access Control List (ACL) engine.

## Features

- **Permission enum**: 9 granular permissions (`ReadUsers`, `WriteUsers`, `DeleteUsers`, etc.)
- **Role class**: Named roles with a set of permissions
- **Role inheritance**: Roles can inherit all permissions from parent roles
- **Multi-role users**: Users can hold multiple roles simultaneously
- **User management**: Create, find, activate/deactivate users
- **Authorization checks**:
  - `hasPermission(userId, perm)` — single permission check
  - `hasAllPermissions(userId, perms)` — require ALL permissions
  - `hasAnyPermission(userId, perms)` — require ANY permission
  - `getEffectivePermissions(userId)` — get union of all permissions
- **Header-only**: Just `#include "Aegis.h"` and go

## Project Structure

```
Aegis-CPP/
├── CMakeLists.txt
├── README.md
├── include/
│   └── Aegis.h          # Full header-only library
└── src/
    └── main.cpp          # Demo application
```

## Build & Run

```bash
mkdir build && cd build
cmake ..
cmake --build .
./AegisCPP
```

## Quick Example

```cpp
#include "Aegis.h"
using namespace Aegis;

int main() {
    AccessControl acl;

    // Create roles with inheritance
    auto& user = acl.createRole("user");
    user.addPermission(Permission::ReadPosts);

    auto& admin = acl.createRole("admin");
    admin.inheritFrom(user);
    admin.addPermission(Permission::WritePosts);
    admin.addPermission(Permission::DeletePosts);

    // Create and assign
    auto& alice = acl.createUser("alice", "alice@example.com");
    acl.assignRole(alice.getId(), "admin");

    // Check permissions
    acl.hasPermission(alice.getId(), Permission::ReadPosts);   // true (inherited)
    acl.hasPermission(alice.getId(), Permission::DeletePosts); // true (direct)
}
```

## Role Hierarchy (default demo)

```
super_admin
  └── admin
        └── moderator
              └── editor
                    └── user
                          └── guest (no permissions)
```
