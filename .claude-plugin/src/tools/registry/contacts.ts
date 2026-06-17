// Contacts tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  CONTACTS,
  CONTACTS_READONLY,
} from "./scopes";

// v1.50 (backlog B5) — shared inputSchema fragment for the Person field groups
// accepted by contacts_create + contacts_update. Each group is an array of
// objects with `additionalProperties: false` at every level, so well-behaved
// MCP clients are rejected early when they send a forbidden field. This is a
// CONVENIENCE layer ONLY — the handler (buildValidatedPerson in
// handlers/contacts.ts) is the authoritative allowlist enforcement and the
// `properties` here MUST stay in lockstep with CONTACT_LEAF_PROPS there.
const PERSON_FIELD_SCHEMAS = {
  names: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        givenName: { type: "string" },
        familyName: { type: "string" },
        middleName: { type: "string" },
        displayName: { type: "string" },
        honorificPrefix: { type: "string" },
        honorificSuffix: { type: "string" },
      },
    },
  },
  emailAddresses: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        value: { type: "string" },
        type: { type: "string" },
        displayName: { type: "string" },
      },
    },
  },
  phoneNumbers: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        value: { type: "string" },
        type: { type: "string" },
      },
    },
  },
  organizations: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        name: { type: "string" },
        title: { type: "string" },
        department: { type: "string" },
      },
    },
  },
  addresses: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        formattedValue: { type: "string" },
        type: { type: "string" },
        streetAddress: { type: "string" },
        extendedAddress: { type: "string" },
        city: { type: "string" },
        region: { type: "string" },
        postalCode: { type: "string" },
        country: { type: "string" },
        countryCode: { type: "string" },
        poBox: { type: "string" },
      },
    },
  },
  biographies: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        value: { type: "string" },
        contentType: { type: "string" },
      },
    },
  },
  urls: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        value: { type: "string" },
        type: { type: "string" },
      },
    },
  },
  userDefined: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        key: { type: "string" },
        value: { type: "string" },
      },
    },
  },
  birthdays: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        date: {
          type: "object",
          additionalProperties: false,
          properties: {
            year: { type: "integer" },
            month: { type: "integer" },
            day: { type: "integer" },
          },
        },
        text: { type: "string" },
      },
    },
  },
} as const;

export const contactsTools: Record<string, ToolDef> = {
  contacts_search: {
    name: "contacts_search",
    description:
      "Search Google People (Contacts) by fuzzy text matching name / email / phone / organization (READ OPERATION; personal contacts ONLY — does NOT include other-contacts auto-harvested from Gmail headers, and does NOT include Workspace directory). Uses the People API `people.searchContacts` endpoint with readMask `names,emailAddresses,phoneNumbers,organizations,biographies,urls,addresses`. Returns {results: SearchResult[]} where each SearchResult wraps a Person resource. Defaults: max_results=10; cap at 30 (anti-DoS + anti-context-flood — a 30-result lookup implies the query is too broad). User-typed content (names[*].displayName, emailAddresses[*].value, phoneNumbers[*].value, biographies[*].value, organizations[*].name, urls[*].value, addresses[*].formattedValue, etc.) is sanitize-wrapped per the standard <untrusted-source> pipeline; Google opaque metadata (resourceName, etag) and closed enums (objectType) pass through unwrapped. First call per (process, account) triggers an internal People-API cache-warm + 3000ms sleep (Google search-index cold-cache quirk; per docs/v1.15-contacts-api.md §4); subsequent same-process calls for the same account are fast.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "Free-text query. Matches against name / email / phone / org. Empty queries are rejected at the handler boundary (the empty-query shape is reserved for internal cache warming).",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 30,
          default: 10,
          description:
            "Maximum number of results (default 10, handler-side cap at 30 as anti-DoS + anti-context-flood guard).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [CONTACTS_READONLY],
    handler: handlers.contactsSearch,
    min_tier: "read",
  },
  contacts_lookup_email: {
    name: "contacts_lookup_email",
    description:
      "Resolve a human-readable name to email address(es) via Google People (Contacts) (READ OPERATION). Designed as the integration primitive for future `gmail_send` / `calendar_create_event` recipient resolution (Phase 3, env-var opt-in). Returns {matches: [{display_name, email_addresses[]}], ambiguous: boolean}. Ambiguity contract: when >1 matches the response field MUST be {ambiguous: true, match_count: N} ONLY — display_name and email_addresses are NEVER echoed on ambiguity (would convert the response into a contact-enumeration oracle); the caller MUST call `contacts_search` to disambiguate (auditable separately). 0 matches returns {matches: [], ambiguous: false}; the caller decides whether to surface this as failure. Filtered to contacts with at least 1 email address (contacts with no email cannot satisfy a recipient-resolution use case). Same cache-warming behavior as `contacts_search` (first call per process+account pays a 3000ms warm; subsequent fast).",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description:
            "Human-readable name fragment (e.g., 'alice', 'Alice Smith'). Empty strings are rejected at the handler boundary.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 10,
          default: 5,
          description:
            "Maximum number of matches to consider for ambiguity check (default 5, handler-side cap at 10). Lower than contacts_search because lookup is for disambiguation, not browse.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
    requiredScopes: [CONTACTS_READONLY],
    handler: handlers.contactsLookupEmail,
    min_tier: "read",
  },
  contacts_get: {
    name: "contacts_get",
    description:
      "Get a single Google People (Contacts) resource by resourceName (READ OPERATION). Returns the full Person resource verbatim from People API `people.get` with personFields `names,emailAddresses,phoneNumbers,organizations,biographies,urls,addresses,birthdays`. Use this after contacts_search or contacts_lookup_email to fetch full detail for a specific contact. The resource_name MUST match /^people\\/c[0-9]{1,32}$/ (handler-side validation BEFORE any SDK call — rejects path traversal, CRLF injection, malformed input). User-typed fields are sanitize-wrapped per the standard <untrusted-source> pipeline; opaque keys (resourceName, etag) and closed enums (objectType) pass through unwrapped.",
    inputSchema: {
      type: "object",
      properties: {
        resource_name: {
          type: "string",
          description:
            "People API resource name (e.g., 'people/c1234567890123456789'). Must match /^people\\/c[0-9]{1,32}$/ — obtained from contacts_search or contacts_lookup_email responses.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["resource_name"],
      additionalProperties: false,
    },
    requiredScopes: [CONTACTS_READONLY],
    handler: handlers.contactsGet,
    min_tier: "read",
  },
  contacts_create: {
    name: "contacts_create",
    description:
      "Create a new personal Google contact via People API `people.createContact` (WRITE OPERATION; requires SAFESPACE_TIER=write or higher + the full `contacts` OAuth scope added in v1.50 — existing accounts must re-run `safespace consent <email> --re-auth`). Accepts an ALLOWLISTED subset of Person field groups: names, emailAddresses, phoneNumbers, organizations, addresses, biographies, urls, userDefined, birthdays. Any other field (photos, metadata, externalIds, relations, imClients, sipAddresses, etc.) is REJECTED — the request body is constructed field-by-field from the allowlist, never passed through. Free-text caps: biographies.value ≤2048 bytes, urls.value ≤512 bytes, userDefined.value ≤512 bytes, all other string leaves ≤1024 bytes. urls[*].value must parse as a URL with scheme http / https / mailto ONLY (javascript:/data:/file: are rejected). At least one field group is required. Returns the created Person resource. NON-DESTRUCTIVE (adds a new contact; does not modify or delete existing ones).",
    inputSchema: {
      type: "object",
      properties: {
        ...PERSON_FIELD_SCHEMAS,
        account_id: {
          type: "string",
          description: "Email of the account to write to; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [CONTACTS],
    handler: handlers.contactsCreate,
    min_tier: "write",
  },
  contacts_update: {
    name: "contacts_update",
    description:
      "Update an existing personal Google contact via People API `people.updateContact` (WRITE OPERATION; requires SAFESPACE_TIER=write or higher + the full `contacts` OAuth scope, v1.50). READ-MODIFY-WRITE: you MUST first call contacts_get to obtain the contact's current `etag`, then pass it here — People API uses it for optimistic concurrency and rejects a stale/missing etag (prevents lost updates). `resource_name` (people/cNNN…) + `etag` are required. Only the field GROUPS you supply are changed (updatePersonFields mask derived from the body); groups you omit are left untouched. Same ALLOWLIST + free-text caps + url-scheme gate as contacts_create. At least one field group is required. Returns the updated Person resource. RECOVERABLE (re-update to revert; this tool never deletes a contact).",
    inputSchema: {
      type: "object",
      properties: {
        resource_name: {
          type: "string",
          description:
            "People API resource name of the contact to update (e.g., 'people/c1234567890123456789'). Must match /^people\\/c[0-9]{1,32}$/. Obtain from contacts_search / contacts_get.",
        },
        etag: {
          type: "string",
          description:
            "The contact's current etag, obtained from a prior contacts_get. Required for optimistic concurrency — People API rejects the update if it is missing or stale.",
        },
        ...PERSON_FIELD_SCHEMAS,
        account_id: {
          type: "string",
          description: "Email of the account to write to; defaults to the most recently used account.",
        },
      },
      required: ["resource_name", "etag"],
      additionalProperties: false,
    },
    requiredScopes: [CONTACTS],
    handler: handlers.contactsUpdate,
    min_tier: "write",
  },
};
