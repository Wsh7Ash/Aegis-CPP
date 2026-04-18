#pragma once
#include "AccessControl.h"
#include <string>
#include <sstream>

namespace Aegis {

// ─── JSON Serializer ───────────────────────────────────────────────────────────
// Lightweight JSON export/import without external dependencies.

class Serializer {
public:
    /// Export the entire ACL configuration to a JSON string.
    static std::string toJSON(const AccessControl& acl) {
        std::ostringstream j;
        j << "{\n";

        // Roles
        j << "  \"roles\": [\n";
        auto roles = acl.listRoles();
        for (size_t i = 0; i < roles.size(); ++i) {
            const auto& role = acl.getRole(roles[i]);
            j << "    {\n";
            j << "      \"name\": \"" << escape(role.getName()) << "\",\n";
            j << "      \"description\": \"" << escape(role.getDescription()) << "\",\n";
            j << "      \"priority\": " << role.getPriority() << ",\n";

            j << "      \"permissions\": [";
            auto perms = role.getPermissions();
            size_t pi = 0;
            for (auto p : perms) {
                if (pi++ > 0) j << ", ";
                j << "\"" << permissionToString(p) << "\"";
            }
            j << "],\n";

            j << "      \"denied\": [";
            auto denied = role.getDeniedPermissions();
            pi = 0;
            for (auto p : denied) {
                if (pi++ > 0) j << ", ";
                j << "\"" << permissionToString(p) << "\"";
            }
            j << "],\n";

            j << "      \"parents\": [";
            auto& parents = role.getParents();
            for (size_t k = 0; k < parents.size(); ++k) {
                if (k > 0) j << ", ";
                j << "\"" << escape(parents[k]) << "\"";
            }
            j << "]\n";

            j << "    }" << (i + 1 < roles.size() ? "," : "") << "\n";
        }
        j << "  ],\n";

        // Users
        j << "  \"users\": [\n";
        auto userIds = acl.listUserIds();
        for (size_t i = 0; i < userIds.size(); ++i) {
            const auto& user = acl.getUser(userIds[i]);
            j << "    {\n";
            j << "      \"id\": " << user.getId() << ",\n";
            j << "      \"username\": \"" << escape(user.getUsername()) << "\",\n";
            j << "      \"email\": \"" << escape(user.getEmail()) << "\",\n";
            j << "      \"active\": " << (user.isActive() ? "true" : "false") << ",\n";

            j << "      \"roles\": [";
            auto& userRoles = user.getRoles();
            size_t ri = 0;
            for (auto& r : userRoles) {
                if (ri++ > 0) j << ", ";
                j << "\"" << escape(r) << "\"";
            }
            j << "],\n";

            j << "      \"attributes\": {";
            auto& attrs = user.getAttributes();
            size_t ai = 0;
            for (auto& [k, v] : attrs) {
                if (ai++ > 0) j << ", ";
                j << "\"" << escape(k) << "\": \"" << escape(v) << "\"";
            }
            j << "}\n";

            j << "    }" << (i + 1 < userIds.size() ? "," : "") << "\n";
        }
        j << "  ]\n";

        j << "}\n";
        return j.str();
    }

    /// Export audit log to JSON.
    static std::string auditToJSON(const AuditLog& log) {
        std::ostringstream j;
        j << "[\n";
        auto& entries = log.getEntries();
        for (size_t i = 0; i < entries.size(); ++i) {
            auto& e = entries[i];
            j << "  {\n";
            j << "    \"action\": \"" << auditActionToString(e.action) << "\",\n";
            j << "    \"userId\": " << e.userId << ",\n";
            j << "    \"result\": " << (e.result ? "true" : "false") << ",\n";
            j << "    \"detail\": \"" << escape(e.detail) << "\"\n";
            j << "  }" << (i + 1 < entries.size() ? "," : "") << "\n";
        }
        j << "]\n";
        return j.str();
    }

private:
    static std::string escape(const std::string& s) {
        std::string r;
        r.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"':  r += "\\\""; break;
                case '\\': r += "\\\\"; break;
                case '\n': r += "\\n"; break;
                case '\t': r += "\\t"; break;
                default:   r += c;
            }
        }
        return r;
    }
};

} // namespace Aegis
