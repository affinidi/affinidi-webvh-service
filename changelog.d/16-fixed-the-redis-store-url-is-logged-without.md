### Fixed — the Redis store URL is logged without credentials

Opening the Redis store logged `redis_url` as configured, including any
username, password or query parameters. The log line now shows the scheme,
host, port and database only.
