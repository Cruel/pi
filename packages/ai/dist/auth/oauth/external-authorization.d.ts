/** Shared validation for listener-free OAuth authorizations owned by a host application. */
import type { OAuthAuthorization } from "../types.ts";
export declare function redirectUriForHost(value: string): string;
export declare function pendingAuthorization(provider: string, url: string, state: string, verifier: string, redirectUri: string): OAuthAuthorization;
export declare function authorizationCallback(provider: string, authorization: OAuthAuthorization, callbackUrl: string, signal: AbortSignal): {
    code: string;
    state: string;
    verifier: string;
    redirectUri: string;
};
//# sourceMappingURL=external-authorization.d.ts.map