# Checkpoint Framework

This framework exists as a way to interact with the Checkpoint API.


## Configuration of credential storage

API Credentials are structured in the same format as `configuration_template.json` and are to be placed in a file named `configuration.json`.

## Configuration of main object

Instantiate the Checkpoint object by passing the Provider1 server configuration from `configuration.json` under the `servers` parameter.

Provider1 server is named "provider1" in the `configuration_template.json` file.
```python
# For Production Provider1 server
host = 'provider1'
c = Checkpoint(config=host, domain='')

# Login is automatic for instantiation
```

After the object has authenticated to the Provider server, queries may be executed to an API service.

A query made to the Provider1 server for a list of domains it has configurations stored :
```python
# Store list of domains
device_list = c.get_domain_list()
```

Domain authentication configurations for new domains need stored in `configuration_template.json` file.

Log out of old domain automatically and log in to new domain : 
```python
# For Production Provider1 server
host = 'provider1'

# Login to domain
domain = '**REDACTED**'

c.login(domain=domain)
```

Grab a list of access-layers for a given domain :
```python
access_layers = c.get_access_layer_list()

# Show first result of access-layers query
print(access_layers['result']['access-layers'][0]['uid'])
```

Grab a list of access-rules for a given access-layer UID :
```python
access_layers = c.get_access_layer_list()

# Show first result of access-layers query
acccess_layer_uid = access_layers['result']['access-layers'][0]['uid']

# Retrieve access-rule specifying an access-layer UID
access_rule = c.get_access_rule_list(acccess_layer_uid)

# Show result of rule query
print(access_rule['result']['rulebase'][0])
```

Always logout to free up sessions :
```python
c.logout()
```
