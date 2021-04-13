import getter from "lodash.get";
import setter from "lodash.set";

import { schema } from "./schema";

class Config {
	public error: Error | undefined;
	public config: object = {};

	public load(options: object): void {
		this.reset();

		const { value, error } = schema.validate(options);

		if (error) {
			this.error = error;
			return;
		}

		this.config = value;
	}

	public reset(): void {
		this.error = undefined;
		this.config = {};
	}

	public get(key: string, defaultValue?: any): any {
		return getter(this.config, key, defaultValue);
	}

	public set(key: string, value: any): void {
		setter(this.config, key, value);
	}

	public getError(): Error | undefined {
		return this.error;
	}

	public hasError(): boolean {
		return !!this.error;
	}
}

export const config = new Config();
