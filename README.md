![OWND Project Logo](https://raw.githubusercontent.com/OWND-Project/.github/main/media/ownd-project-logo.png)

# OWND Project

The OWND Project is a non-profit project that aims to realize more trustworthy communication through the social implementation of individual-centered digital identities.

This project was created as part of the "Trusted Web" use case demonstration project promoted by the Digital Market Competition Headquarters, Cabinet Secretariat.

We will develop a white-label digital identity wallet that complies with international standards and a federated messaging application that supports E2E encryption as open source software, and discuss governance to ensure trust.

[OWND Project Briefing Material](https://github.com/OWND-Project/.github/blob/main/profile/ownd-project.pdf)

[Learn more about Trusted Web](https://trustedweb.go.jp/)

# Project List

## Degital Identity Wallet

- [OWND Wallet Android]()
- [OWND Wallet iOS]()

## Issuance of Verifiable Credentials

- [OWND Project VCI]()

## Messaging Services

- [OWND Messenger Server]()
  - It is a product of this repository.
- [OWND Messenger Client]()
- [OWND Messenger React SDK]()

# About the OWND Messenger Server setup

This procedure is for developers. For deploying to the production environment, you should refer to codebuild/Dockerfile and create an appropriate procedure for the environment you are deploying to.

Since OWND Messenger Server is based on Synapse, please also refer to the Synapse environment setup instructions if necessary.

https://matrix-org.github.io/synapse/latest/development/contributing_guide.html

## Prerequirement

- Python version 3
- [venv](https://docs.python.org/3/library/venv.html)
- PostgreSQL's C header files
- [libicu](https://docs.python.org/3/library/venv.html)

## Install

### Get the source code

Before executing the following commands, you must fork the repository on Github

```bash
$ git clone git@github.com:YOUR_GITHUB_USER_NAME/synapse.git
$ git checkout develop
```

### Install the dependencies

As a dependency management tool, Poetry must be installed.

```bash
$ pip install --user pipx
$ pipx install poetry==1.5.1  # Problems with Poetry 1.6, see https://github.com/matrix-org/synapse/issues/16147
```

```bash
$ cd path/where/you/have/cloned/the/repository
$ poetry install --extras all
```

## Config

A sample configuration is shown below. 

homeserver.yaml
```yaml
server_name: "localhost"
public_baseurl: "http://localhost:8008/"
request_object_signing_kid: "kid123"
pid_file: DATADIR/homeserver.pid
listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['::1', '127.0.0.1']
    resources:
      - names: [client, federation]
        compress: false
database:
  name: sqlite3
  args:
    database: DATADIR/homeserver.db
serve_server_wellknown: true
enable_registration: true
enable_registration_without_verification: true
log_config: "log_config.yaml"
media_store_path: DATADIR/media_store
signing_key_path: "signing.key"
trusted_key_servers:
  - server_name: "localhost"
registration_shared_secret: secretstring
report_stats: false

# WORKAROUND: ###############################################################
# The combination of SIOPv2 and Matrix's original authentication method 
# (User Interactive Authentication) is not working properly in some cases. 
# This is a temporary configuration to reduce the frequency of this problem.
ui_auth:
  session_timeout: "90d"
#############################################################################

# WORKAROUND ################################################################
# SIOPv2 sign-up and sign-in was implemented as a variant of GitHub 
# login with OIDC. Therefore, the following settings must remain in the configuration.
# After the SIOPv2 and OIDC related implementations are properly modified, 
# the following contents will also be modified.
oidc_providers:
  - idp_id: github
    idp_name: SIOPv2
    discover: false
    issuer: "https://self-issued.me/v2"
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    authorization_endpoint: "https://example.com/oauth/authorize"
    token_endpoint: "https://example.com/oauth/access_token"
    userinfo_endpoint: "https://api.example.com/user"
    scopes: ["read:user"]
#############################################################################
    user_mapping_provider:
      config:
        subject_claim: "sub"
        confirm_localpart: true
```

log_config.yaml
```yaml
version: 1

formatters:
  precise:
    format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s'

handlers:
  console:
    class: logging.StreamHandler
    formatter: precise

loggers:
    synapse.storage.SQL:
        # beware: increasing this to DEBUG will make synapse log sensitive
        # information such as access tokens.
        level: INFO
        
root:
    level: INFO
    handlers: [console]

disable_existing_loggers: false
```

For more information on each item in the configurations, see the following pages.

https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html

## Running Synapse via poetry

```bash
$ poetry run python -m synapse.app.homeserver -c homeserver.yaml
```