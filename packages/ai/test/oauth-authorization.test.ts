import { afterEach, describe, expect, it, vi } from "vitest";
import { createModels } from "../src/models.ts";
import { anthropicProvider } from "../src/providers/anthropic.ts";
import { openaiProvider } from "../src/providers/openai.ts";

const hostId = "e61bbe28-07ef-466d-8e5d-a344f94ab305";
const redirectUri = "http://127.0.0.1:3000/auth/callback";

describe("Embeddable OAuth authorization", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("prepares independently correlated browser authorizations and completes them without a listener", async () => {
		const models = createModels();
		models.setProvider(openaiProvider());
		const requests: URLSearchParams[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_url: unknown, init: RequestInit) => {
				requests.push(new URLSearchParams(String(init.body)));
				return Response.json({
					access_token: `access-${requests.length}`,
					refresh_token: `refresh-${requests.length}`,
					expires_in: 3600,
					id_token: "id-token",
					scope: "openid chatgpt.tokens.use.direct",
				});
			}),
		);
		const options = { redirectUri, agentName: "Example Host", getDeviceId: () => hostId };
		const [first, second] = await Promise.all([
			models.beginOAuth("openai", options),
			models.beginOAuth("openai", options),
		]);
		expect(first.state).not.toBe(second.state);
		expect(new URL(first.url).searchParams.get("agent_name_hint")).toBe("Example Host");
		expect(new URL(first.url).searchParams.get("redirect_uri")).toBe(redirectUri);
		expect(first.context).not.toContain("access-");
		const callback = (state: string) => {
			const url = new URL(redirectUri);
			url.searchParams.set("state", state);
			url.searchParams.set("code", "some-code");
			url.searchParams.set("client_id", "issued-client");
			return url.toString();
		};
		await expect(models.completeOAuth("openai", first, callback(second.state))).rejects.toThrow(/state mismatch/i);
		expect(requests).toHaveLength(0);
		const credential = await models.completeOAuth("openai", first, callback(first.state));
		expect(credential).toMatchObject({ type: "oauth", access: "access-1", clientId: "issued-client" });
		expect(requests[0]?.get("code_verifier")).toBeTruthy();
		expect(requests[0]?.get("redirect_uri")).toBe(redirectUri);
		expect((await models.getAuth("openai"))?.auth.apiKey).toBe("access-1");
		await expect(models.completeOAuth("openai", second, "https://evil.example/auth/callback?code=x")).rejects.toThrow(
			/callback/i,
		);
	});

	it("rejects providers without a two-phase authorization interface", async () => {
		const models = createModels();
		await expect(models.beginOAuth("missing")).rejects.toThrow(/unknown provider/i);
		models.setProvider(anthropicProvider());
		expect(models.getProvider("anthropic")?.auth.oauth?.beginAuthorization).toBeUndefined();
		await expect(models.beginOAuth("anthropic")).rejects.toThrow(/does not support external OAuth authorization/i);
	});
});
