import Hapi from "@hapi/hapi";

import { plugin } from "../src";

const createServer = () => new Hapi.Server({ debug: { request: ["*"] } });

const sendRequest = (server: Hapi.Server, url: string) => {
	try {
		server.route({
			method: "GET",
			path: "/",
			handler: () => [],
		});

		server.route({
			method: "GET",
			path: "/auth",
			handler: () => [],
			options: { auth: "localhost" },
		});
	} catch (err) {
		console.debug(err.message);
	}

	return server.inject({ method: "GET", url });
};

describe("blacklist", () => {
	describe("Strategy - Global", () => {
		it("should return 200", async () => {
			const server = createServer();
			await server.register({ plugin });

			const response = await sendRequest(server, "/");

			expect(response.statusCode).toBe(200);
		});

		it("should return 401", async () => {
			const server = createServer();
			await server.register({ plugin, options: { blacklist: ["127.*"] } });

			const response = await sendRequest(server, "/");

			expect(response.statusCode).toBe(401);
		});
	});

	describe("Strategy - Scheme", () => {
		it("should return 200", async () => {
			const server = createServer();
			await server.register({ plugin, options: { strategy: "auth" } });
			server.auth.strategy("localhost", "blacklist");

			const responseGlobal = await sendRequest(server, "/");
			expect(responseGlobal.statusCode).toBe(200);

			const responseLocal = await sendRequest(server, "/auth");
			expect(responseLocal.statusCode).toBe(200);
		});

		it("should return 401", async () => {
			const server = createServer();
			await server.register({
				plugin,
				options: { strategy: "auth", blacklist: ["127.*"] },
			});
			server.auth.strategy("localhost", "blacklist");

			const responseGlobal = await sendRequest(server, "/");
			expect(responseGlobal.statusCode).toBe(200);

			const responseLocal = await sendRequest(server, "/auth");
			expect(responseLocal.statusCode).toBe(401);
		});
	});
});
