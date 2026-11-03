import { afterEach, describe, expect, it, vi } from "vitest";
import { createModels } from "../src/models.ts";
import { anthropicProvider } from "../src/providers/anthropic.ts";
import { openaiCodexProvider } from "../src/providers/openai-codex.ts";
import { openrouterProvider } from "../src/providers/openrouter.ts";
import { radiusProvider } from "../src/providers/radius.ts";

const hostCallback = "http://127.0.0.1:3000/auth/callback";
const accessToken = `${Buffer.from("{}").toString("base64")}.${Buffer.from(
	JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: "account-1" } }),
).toString("base64")}.sig`;

describe("Listener-free OAuth provider adapters", () => {
	afterEach(() => vi.unstubAllGlobals());

	for (const [providerId, factory, tokenUrl, authParam] of [
		["anthropic", anthropicProvider, "https://platform.claude.com/v1/oauth/token", "redirect_uri"],
		["openai-codex", openaiCodexProvider, "https://auth.openai.com/oauth/token", "redirect_uri"],
		["openrouter", openrouterProvider, "https://openrouter.ai/api/v1/auth/keys", "callback_url"],
		["radius", radiusProvider, "https://radius.pi.dev/v1/oauth/token", "redirect_uri"],
	] as const) {
		it(`${providerId}: prepares independent authorizations, rejects forged callbacks and exchanges credentials`, async () => {
			const exchanges: Array<{ uri: string; body: string }> = [];
			vi.stubGlobal(
				"fetch",
				vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
					const uri = String(input);
					if (uri.endsWith("/v1/oauth"))
						return Response.json({ authorizationEndpoint: "https://radius.example/authorize" });
					if (uri !== tokenUrl) throw new Error(`Unexpected HTTP request: ${uri}`);
					exchanges.push({ uri, body: String(init?.body) });
					if (providerId === "openrouter") return Response.json({ key: "issued-router-key" });
					return Response.json({
						access_token: providerId === "openai-codex" ? accessToken : "issued-access",
						refresh_token: "issued-refresh",
						expires_in: 3600,
					});
				}),
			);
			const models = createModels();
			models.setProvider(factory());
			const [first, second] = await Promise.all([
				models.beginOAuth(providerId, { redirectUri: hostCallback, agentName: "Studio" }),
				models.beginOAuth(providerId, { redirectUri: hostCallback, agentName: "Studio" }),
			]);
			expect(first.state).not.toBe(second.state);
			if (providerId === "anthropic") {
				const context = JSON.parse(first.context) as { verifier: string };
				expect(first.state).not.toBe(context.verifier);
			}
			expect(first.url).not.toBe(second.url);
			expect(new URL(first.url).searchParams.get(authParam)).toBe(hostCallback);
			const callback = (uri: string, state: string) => {
				const url = new URL(uri);
				url.searchParams.set("code", "callback-code");
				url.searchParams.set("state", state);
				return url.toString();
			};
			await expect(models.completeOAuth(providerId, first, callback(hostCallback, second.state))).rejects.toThrow(
				/state mismatch/,
			);
			await expect(
				models.completeOAuth(providerId, first, callback("https://evil.example/auth/callback", first.state)),
			).rejects.toThrow(/redirect URI/);
			await expect(
				models.completeOAuth(providerId, first, `${hostCallback}?error=access_denied&state=${first.state}`),
			).rejects.toThrow(/authorization failed/);
			expect(exchanges).toHaveLength(0);
			const credential = await models.completeOAuth(providerId, first, callback(hostCallback, first.state));
			expect(credential.type).toBe("oauth");
			if (credential.type !== "oauth") throw new Error("Expected OAuth credential");
			expect(credential.access).toBe(
				providerId === "openrouter"
					? "issued-router-key"
					: providerId === "openai-codex"
						? accessToken
						: "issued-access",
			);
			expect(exchanges).toHaveLength(1);
			expect((await models.getAuth(providerId))?.auth).toBeDefined();
			if (providerId === "anthropic") {
				const tokenRequest = JSON.parse(exchanges[0]!.body) as { state: string; code_verifier: string };
				expect(tokenRequest.state).toBe(first.state);
				expect(tokenRequest.code_verifier).not.toBe(first.state);
			}
			const body =
				providerId === "anthropic"
					? JSON.parse(exchanges[0]!.body)
					: providerId === "openrouter"
						? JSON.parse(exchanges[0]!.body)
						: new URLSearchParams(exchanges[0]!.body);
			expect(
				providerId === "openrouter" ? body.code : body instanceof URLSearchParams ? body.get("code") : body.code,
			).toBe("callback-code");
		});
	}

	it("OpenRouter requires an app callback and includes state in its authorization URL", async () => {
		const models = createModels();
		models.setProvider(openrouterProvider());
		await expect(models.beginOAuth("openrouter")).rejects.toThrow(/requires a host callback/);
		const authorization = await models.beginOAuth("openrouter", {
			redirectUri: "https://studio.example/auth/callback",
		});
		expect(new URL(authorization.url).searchParams.get("state")).toBe(authorization.state);
	});

	it("separates provider contexts and rejects malformed or expired attempts", async () => {
		const models = createModels();
		models.setProvider(anthropicProvider());
		models.setProvider(openrouterProvider());
		const auth = await models.beginOAuth("anthropic", { redirectUri: hostCallback });
		const callback = `${hostCallback}?code=x&state=${encodeURIComponent(auth.state)}`;
		await expect(models.completeOAuth("openrouter", auth, callback)).rejects.toThrow(/context/);
		const context = JSON.parse(auth.context) as { createdAt: number };
		context.createdAt = Date.now() - 16 * 60_000;
		await expect(
			models.completeOAuth("anthropic", { ...auth, context: JSON.stringify(context) }, callback),
		).rejects.toThrow(/expired/);
		await expect(models.beginOAuth("anthropic", { redirectUri: "http://evil.example/callback" })).rejects.toThrow(
			/HTTPS or HTTP loopback/,
		);
	});
});
