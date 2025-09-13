# Burp Collaborator Bridge

This Burp Suite extension exposes a simple API to bridge Python scripts to Burp Suite's Collaborator client

## Usage

1. Load the jar within Burp.
2. Navigate to the 'Collaborator Bridge' tab.
3. Set/Confirm the 'Host' and 'Port'.
4. Click the 'Start' button.
5. Use with Python as described below.

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
