import Joi from "@hapi/joi";

const headers = [
	"x-client-ip",
	"x-forwarded-for",
	"cf-connecting-ip",
	"fastly-client-ip",
	"true-client-ip",
	"x-real-ip",
	"x-cluster-client-ip",
	"x-forwarded",
	"forwarded-for",
	"forwarded",
];

export const schema = Joi.object({
	/**
	 * The strategy used to perform the blacklist checks.
	 */
	strategy: Joi.string()
		.valid("auth", "global")
		.default("global"),
	/**
	 * The IP addresses or patterns that are granted access.
	 */
	blacklist: Joi.array()
		.items(Joi.string())
		.default([]),
	/**
	 * Whether or not we will check headers for the IP address.
	 */
	trustHeaders: Joi.boolean().default(false),
	/**
	 * The headers that should be parsed if we trust headers.
	 */
	headers: Joi.array()
		.items(Joi.string())
		.valid(...headers)
		.default(headers),
});
