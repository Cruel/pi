import { afterEach, describe, expect, it, vi } from "vitest";
import { anthropicOAuth } from "../src/auth/oauth/anthropic.ts";
import { openaiCodexOAuth } from "../src/auth/oauth/openai-codex.ts";
import { openRouterOAuth } from "../src/auth/oauth/openrouter.ts";
import { createRadiusOAuth } from "../src/auth/oauth/radius.ts";
import type { AuthEvent, ProviderAuthInteraction } from "../src/auth/types.ts";

const signal = new AbortController().signal;

function json(body: unknown): Response {
	return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
}

function callbackInteraction(
	method: "browser" | undefined,
	callbackCode: string,
	callbackUri?: string,
): { interaction: ProviderAuthInteraction; events: AuthEvent[] } {
	const events: AuthEvent[] = [];
	const interaction: ProviderAuthInteraction = {
		signal,
		notify: (event) => {
			events.push(event);
		},
		prompt: async (prompt) => {
			if (prompt.type === "select") return method ?? "browser";
			if (prompt.type !== "manual_code") throw new Error("Unexpected prompt");
			const authorize = new URL(events.find((event) => event.type === "auth_url")?.url ?? "");
			const uri =
				callbackUri ??
				authorize.searchParams.get("redirect_uri") ??
				authorize.searchParams.get("callback_url") ??
				"";
			const result = new URL(uri);
			result.searchParams.set("code", callbackCode);
			const state = authorize.searchParams.get("state");
			if (state) result.searchParams.set("state", state);
			return result.toString();
		},
	};
	return { interaction, events };
}

describe("Externally handled OAuth browser callbacks", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("Anthropic accepts the externally routed code and exchanges with the matching redirect URI", async () => {
		const redirectUri = "http://localhost:53692/callback";
		const { interaction, events } = callbackInteraction("browser", "anthropic-code");
		let exchange: Record<string, string> = {};
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_input: unknown, init?: RequestInit) => {
				exchange = JSON.parse(String(init?.body)) as Record<string, string>;
				return json({ access_token: "a", refresh_token: "r", expires_in: 3600 });
			}),
		);
		const credential = await anthropicOAuth.login(interaction, {
			callback: { mode: "external", redirectUri },
		});
		expect(credential.access).toBe("a");
		expect(exchange.code).toBe("anthropic-code");
		expect(exchange.redirect_uri).toBe(redirectUri);
		expect(
			(events.find((event) => event.type === "auth_url") as Extract<AuthEvent, { type: "auth_url" }>).url,
		).toContain("redirect_uri=");
	});

	it("OpenRouter requires a unique external URI and exchanges the supplied callback code", async () => {
		const uri = "http://127.0.0.1:3000/oauth/callback/unpredictable-attempt-id";
		const { interaction, events } = callbackInteraction(undefined, "openrouter-code");
		const forms: Record<string, string>[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_input: unknown, init?: RequestInit) => {
				forms.push(JSON.parse(String(init?.body)) as Record<string, string>);
				return json({ key: "openrouter-key" });
			}),
		);
		await expect(openRouterOAuth.login(interaction, { callback: { mode: "external" } })).rejects.toThrow(
			"redirectUri unique",
		);
		const credential = await openRouterOAuth.login(interaction, {
			callback: { mode: "external", redirectUri: uri },
		});
		expect(credential.access).toBe("openrouter-key");
		expect(forms[0]?.code).toBe("openrouter-code");
		expect(
			new URL(
				(events.find((event) => event.type === "auth_url") as Extract<AuthEvent, { type: "auth_url" }>).url,
			).searchParams.get("callback_url"),
		).toBe(uri);
	});

	it("Radius validates external callback state before exchanging a code", async () => {
		const { interaction } = callbackInteraction("browser", "radius-code");
		const requests: string[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
				const url = input instanceof Request ? input.url : String(input);
				requests.push(url);
				if (url.endsWith("/v1/oauth")) return json({ authorizationEndpoint: "https://gateway.example/authorize" });
				if (url.endsWith("/v1/oauth/token")) {
					const params = new URLSearchParams(String(init?.body));
					expect(params.get("code")).toBe("radius-code");
					return json({ access_token: "a", refresh_token: "r", expires_in: 3600 });
				}
				throw new Error("Unexpected request");
			}),
		);
		const oauth = createRadiusOAuth({ name: "Radius", gateway: "https://gateway.example" });
		const credential = await oauth.login(interaction, { callback: { mode: "external" } });
		expect(credential.access).toBe("a");
		expect(requests).toEqual(["https://gateway.example/v1/oauth", "https://gateway.example/v1/oauth/token"]);
	});

	it("Codex browser mode rejects nonregistered redirects before opening a listener", async () => {
		const { interaction } = callbackInteraction("browser", "codex-code");
		await expect(
			openaiCodexOAuth.login(interaction, {
				callback: { mode: "external", redirectUri: "https://example.com/callback" },
			}),
		).rejects.toThrow("requires the registered redirect URI");
	});
});
