import Boom from "@hapi/boom";
import Hapi, { AuthCredentials } from "@hapi/hapi";
import { discover } from "@konceiver/remote-address";
import * as mm from "micromatch";

import { config } from "./config";

export const authenticate = (
	request: Hapi.Request,
	h: Hapi.ResponseToolkit
) => {
	const credentials = config.get("trustHeaders")
		? discover(request, config.get("headers"))
		: request.info.remoteAddress;

	if (!credentials) {
		return Boom.unauthorized();
	}

	for (const ip of config.get("blacklist")) {
		if (mm.isMatch(credentials, ip)) {
			return Boom.unauthorized();
		}
	}

	if (config.get("strategy") === "auth") {
		return h.authenticated({
			credentials: (credentials as unknown) as AuthCredentials,
		});
	}

	return h.continue;
};
