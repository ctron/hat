# HAT – Hono Admin Tool [![GitHub release](https://img.shields.io/github/release/ctron/hat.svg)](https://github.com/ctron/hat/releases)

Getting help:

    hat --help

## Global switches

Temporarily use a different context (with `-c` or `--context`):

    hat -c context2 device create …

Or override a tenant (with `-t` or `--tenant`):

    hat -t my.tenant device get …

## Managing contexts

Create a new context:

    hat context create foo https://device-registry.hono.my

Create a new context with credentials:

    hat context create foo https://device-registry.hono.my --username <username> --password <password>

Create a new context, using local Kubernetes token:

    hat context create foo https://device-registry.hono.my --use-kubernetes

Update an existing context:

    hat context update foo --url https://device-registry.hono.my
    hat context update foo --username <username> --password <password>
    hat context update foo --use-kubernetes

Delete an existing context:

    hat context delete foo

Switch to an existing context:

    hat context switch foo

List existing contexts:

    hat context list

### Default tenant

It is possible to set a *default tenant*, which is used on all calls when using
this context.

Set a default tenant when creating a context:

    hat context create foo https://device-registry.hono.my --tenant <tenant>

Or update later:

    hat context update foo https://device-registry.hono.my --tenant <tenant>

It is possible to override the default tenant with `-t` or `--tenant`:

    hat device create -t my-tenant 4711

Or by setting the environment variable `HAT_TENANT`:

    HAT_TENANT=foo hat device create 4711

## Tenants

Creating a new tenant:

    hat tenant create my-tenant

Creating a new tenant with payload:

    hat tenant create my-tenant '{"enabled": false}'

Getting a tenant:

    hat tenant get my-tenant

Deleting a tenant:

    hat tenant delete my-tenant

Enable/Disable a tenant:

    hat tenant enable my-tenant
    hat tenant disable my-tenant
    
## Device registrations

Register a new device:

    hat device create 4711

Register a new device with payload:

    hat device create 4711 '{…}'

Inspect the device:

    hat device get 4711

Enable/Disable a device:

    hat device enable 4711
    hat device disable 4711

### Set via

You can also set the "via" attribute directly:

    hat device set-via 4711 my-gw

### Set defaults entry

Set a defaults entry using:

    hat device set-defaults 4711 key value

The value will be converted into a JSON value. If it cannot
be parsed, it will be stored as a string (depending on the
shell you are using, you might need different quotation marks):

    hat device set-defaults 4711 key true           # Booolean: true
    hat device set-defaults 4711 key '"true"'       # String: true
    hat device set-defaults 4711 key 123            # Number: 123
    hat device set-defaults 4711 key '"123"'        # String: 123
    hat device set-defaults 4711 key foobar         # String: foobar
    hat device set-defaults 4711 key '{"foo":123}'  # Object: {"foo":123}

Delete an entry by omitting the value:

    hat device set-defaults 4711 key value

## Credentials

Replace credentials:

    hat creds set device1 '[]'

Clear all credentials:

    hat creds set device1

Add a password:

    hat creds add-password device1 sensor1 password

Set password as only password:

    hat creds set-password device1 sensor1 password

Set password with pre-hashed password:

    hat creds set-password device1 sensor1 password --hash sha-512

Set PSK:

    hat creds set-psk device1 sensor1 PSK

Enable X509:

    hat creds enable-x509 device1 sensor1
