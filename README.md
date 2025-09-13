# Burp Collaborator Bridge

This Burp Suite extension exposes a simple API to bridge Python scripts to Burp Suite's Collaborator client

## Usage

Get extension's health
```
curl -s http://localhost:8090/health
```

Get a new payload
```
curl -s http://localhost:8090/payload
```

Get all interactions (new and old)
```
curl -s http://localhost:8090/interactions
```

Get new interactions (new since last /interactions call)
```
curl -s http://localhost:8090/interactions |jq '[ .[] |select(.new == true) ]'
```

Note: This extension tracks historic interactions within memory. To clear interactions, reload the extension.

## License

This project is licensed under the [MIT License](LICENSE).
