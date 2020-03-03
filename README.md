# HAT – Hono Admin Tool [![GitHub release](https://img.shields.io/github/release/ctron/hat.svg)](https://github.com/ctron/hat/releases)

Getting help:

    hat --help

## Global switches

Temporarily use a different context (with `-c` or `--context`):

    hat -c context2 reg create …

## Managing contexts

Create a new context:

    hat context create foo https://device-registry.hono.my

Create a new context with credentials:

    hat context create foo https://device-registry.hono.my --username <username> --password <password>

Update an existing context:

    hat context update foo https://device-registry.hono.my
    hat context update foo https://device-registry.hono.my --username <username> --password <password>

Delete an existing context:

    hat context delete foo

Switch to an existing context:

    hat context switch foo

### Default tenant

It is possible to set a *default tenant*, which is used on all calls when using
this context.

Set a default tenant when creating a context:

    hat context create foo https://device-registry.hono.my --tenant <tenant>

Or update later:

    hat context update foo https://device-registry.hono.my --tenant <tenant>

It is possible to override the default tenant with `-t` or `--tenant`:

    hat reg create -t my-tenant 4711 '{…}'

**Note**: The default is the Eclipse Hono API.

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

Enable a device:

    hat device enable 4711

Disable a device:

    hat device disable 4711

## Credentials

Add a password:

    hat cred add-password device1 sensor1 password

Set password as only password:

    hat cred set-password device1 sensor1 password

Set password with pre-hashed password:

    hat cred set-password device1 sensor1 password --hash sha-512
