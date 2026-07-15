// Pack-aware wrapper around the shared service-token allowlist factory.
//
// The low-level parse / state / membership / summary logic lives in
// policy/service-token-allowlist.ts (`makeServiceTokenAllowlist`) — CONSUME it,
// do not reinvent. This module binds a `ServiceTokenPack` (or a minimal env+regex
// spec) so a connector's thin allowlist module is a one-liner instantiate +
// re-export of connector-specific names.
//
// SECURITY: this remains pure POLICY membership. Egress enforcement (HMAC-hash
// of a denied id, audit denied-event, throw) stays in tools/egress.ts, untouched.
// Each connector module still EXPORTS its own ID regex as a named const for the
// handler's pre-egress syntactic validation.

import type { ServiceTokenPack } from "../tools/service-token-pack";
import {
  makeServiceTokenAllowlist,
  type ServiceTokenAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-allowlist";

export type { ServiceTokenAllowlist, ServiceTokenAllowlistState };

/** Minimal input accepted by the pack-aware allowlist factory (full pack or the
 *  two fields it actually reads). */
export type ServiceTokenRecipientAllowlistSpec = Pick<
  ServiceTokenPack,
  "env" | "recipientIdSpec"
>;

/** Build the state reader + membership predicate for one service-token connector
 *  from its pack (or an equivalent env+regex spec). */
export function makeServiceTokenRecipientAllowlist(
  packOrSpec: ServiceTokenRecipientAllowlistSpec,
): ServiceTokenAllowlist {
  return makeServiceTokenAllowlist({
    idRe: packOrSpec.recipientIdSpec.regex,
    envAllow: packOrSpec.env.recipientAllow,
    envExtra: packOrSpec.env.recipientAllowExtra,
  });
}
