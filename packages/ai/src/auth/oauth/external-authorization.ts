/** Shared validation for listener-free OAuth authorizations owned by a host application. */
import type { OAuthAuthorization } from "../types.ts";

type Pending = {
	provider: string;
	state: string;
	verifier: string;
	redirectUri: string;
	createdAt: number;
};

export function redirectUriForHost(value: string): string {
	const url = new URL(value);
	if (
		(url.protocol !== "https:" &&
			(url.protocol !== "http:" || !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) ||
		url.username ||
		url.password ||
		url.search ||
		url.hash
	) {
		throw new Error("OAuth redirect URI must use HTTPS or HTTP loopback without credentials, query, or fragment");
	}
	return url.toString();
}

export function pendingAuthorization(
	provider: string,
	url: string,
	state: string,
	verifier: string,
	redirectUri: string,
): OAuthAuthorization {
	return {
		url,
		state,
		context: JSON.stringify({ provider, state, verifier, redirectUri, createdAt: Date.now() } satisfies Pending),
	};
}

export function authorizationCallback(
	provider: string,
	authorization: OAuthAuthorization,
	callbackUrl: string,
	signal: AbortSignal,
): { code: string; state: string; verifier: string; redirectUri: string } {
	signal.throwIfAborted();
	let pending: Partial<Pending>;
	let callback: URL;
	try {
		pending = JSON.parse(authorization.context) as Partial<Pending>;
		callback = new URL(callbackUrl);
	} catch {
		throw new Error("Invalid OAuth authorization context or callback URL");
	}
	const now = Date.now();
	if (
		!pending ||
		pending.provider !== provider ||
		typeof pending.state !== "string" ||
		pending.state !== authorization.state ||
		typeof pending.verifier !== "string" ||
		!pending.verifier ||
		typeof pending.redirectUri !== "string" ||
		typeof pending.createdAt !== "number" ||
		pending.createdAt > now ||
		now - pending.createdAt > 15 * 60_000
	) {
		throw new Error("Invalid or expired OAuth authorization context");
	}
	const redirect = new URL(pending.redirectUri);
	if (callback.origin !== redirect.origin || callback.pathname !== redirect.pathname) {
		throw new Error("OAuth callback URL does not match the requested redirect URI");
	}
	if (callback.searchParams.get("state") !== pending.state) {
		throw new Error("OAuth state mismatch");
	}
	const error = callback.searchParams.get("error");
	if (error) throw new Error(`OAuth authorization failed: ${error}`);
	const code = callback.searchParams.get("code");
	if (!code) throw new Error("Missing OAuth authorization code");
	return { code, state: pending.state, verifier: pending.verifier, redirectUri: pending.redirectUri };
}
