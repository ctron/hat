# HAT – Hono Admin Tool

Getting help:

    hat --help

## Managing contexts

Create a new context:

    hat context create foo https://device-registry.hono.my

Update an existing context:

    hat context update foo https://device-registry.hono.my

Delete an existing context:

    hat context delete foo

Switch to an existing context:

    hat context switch foo

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

    hat reg my-tenant 4711

Register a new device with payload:

    hat reg my-tenant 4711 '{…}'

## Credentials

Add a password:

    hat cred add-password my-tenant sensor1 sha-512 password

Add a password, creating a new credentials set if necessary:

    hat cred add-password my-tenant sensor1 sha-512 password --device 4711

Set password as only password:

    hat cred set-password my-tenant sensor1 sha-512 password
    hat cred set-password my-tenant sensor1 sha-512 password --device 4711


