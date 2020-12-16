import { Server } from "@hapi/hapi";
import { authenticate } from "./authenticate";
import { config } from "./config";

export const plugin = {
	pkg: require("../package.json"),
	once: true,
	register(server: Server, options = {}) {
		// Configure...
		config.load(options);

		if (config.hasError()) {
			throw config.getError();
		}

		// Register...
		if (config.get("strategy") === "auth") {
			server.auth.scheme("blacklist", () => ({
				authenticate(request, h) {
					return authenticate(request, h);
				},
			}));
		} else {
			server.ext({
				type: "onRequest",
				async method(request, h) {
					return authenticate(request, h);
				},
			});
		}
	},
};
