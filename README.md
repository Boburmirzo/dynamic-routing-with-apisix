# Dynamic routing based on JWT Claim with Apache APISIX and Okta

## Demo: JWT Token’s claim-based dynamic routing

In this demo, we use the existing public backend API called [Conference API](https://conferenceapi.azurewebsites.net/?format=json) with conference sessions, speakers, and topics information. Let’s assume that we want to filter and retrieve only sessions belonging to a specific speaker who is logged into the system using its credentials such as a JWT token. For example, `https://conferenceapi.azurewebsites.net/speaker/1/sessions`

the request shows only sessions of a speaker with a unique id and this unique id comes from the JWT token claim as a part of its payload. Look at the below decoded token payload structure, there is a `speakerId` field also included:

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/73c611f4-b189-41f4-a06f-a807a11ce1b9/Untitled.png)

In this scenario, we send requests to the same [Route](https://apisix.apache.org/docs/apisix/terminology/route/) at API Gateway and it computes the dynamic URI  from the authorization header and forwards the request to the URI (See below diagram to understand the flow). To do so, we are going to implement a dynamic routing at the Apache APISIX API Gateway level based on the JWT token's claim through the use of the following plugins:

1. [openid-connect](https://apisix.apache.org/docs/apisix/plugins/openid-connect/) plugin that interacts with the identity provider(IdP) and can intercept unauthenticated requests in time to back-end applications. As an identity provider, we use the [Okta](https://www.okta.com/) that issues a JWT token with our custom claim and validates the JWT token.  Or you can use other IdPs such as [Keycloak](https://www.keycloak.org/), and [Ory Hydra](https://www.ory.sh/hydra/), or you can even use [jwt-plugin](https://apisix.apache.org/docs/apisix/plugins/jwt-auth/) to create a JWT token, and authenticate and authorize requests.
2. [serverless-pre-function](https://apisix.apache.org/docs/apisix/plugins/serverless/) plugin to write a custom Lua function code that intercepts the request, decodes, parses a JWT token claim and stores the value of the claim in a new custom header to further make authorization decisions.
3. [proxy-rewrite](https://apisix.apache.org/docs/apisix/plugins/proxy-rewrite/) plugin, once we have the claim in the header, we use this plugin as the request forwarding mechanism to determine which URI path needs to be used for retrieving speaker-specific sessions based on the [Nginx header variable](https://nginx.org/en/docs/http/ngx_http_core_module.html) in our case it is `speakerId` that dynamically changes to create different paths `/speaker/$http_speakerId/sessions` . The plugin will forward the request to the related resource in the Conference API.

Once we understood what we are going to cover throughout the demo, let’s check the prerequisites to get started with configuring the above scenario and successfully complete the tutorial.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) is used to installing the containerized etcd and APISIX.
- [curl](https://curl.se/) is used to send requests to APISIX for configuring route, upstream and plugin configs. You can also use easy tools such as [Postman](https://www.postman.com/) to interact with the API.
- Apache APISIX is installed in your target environment. APISIX can be easily installed and started with the following [quick start guide](https://docs.api7.ai/apisix/getting-started/#get-apisix).
- Make sure that your [OKTA](https://www.okta.com/) account is created, you registered a new app (You can follow this guide [Configuring Okta](https://api7.ai/blog/how-to-use-apisix-auth-with-okta#:~:text=ready%20for%20use.-,Step%201%3A%20Configuring%20Okta,-Log%20in%20to)), a[dd a custom claim to a token](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/#add-a-custom-claim-to-a-token) using Okta dashboard, and [request a token that contains the custom claim](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/#request-a-token-that-contains-the-custom-claim) called `speakerId`.

### Configure the backend service (upstream)

You will need to configure the backend service for Conference API that you want to route requests to. This can be done by adding an upstream server in the Apache APISIX through the [Admin API](https://apisix.apache.org/docs/apisix/admin-api/).

```bash
curl "http://127.0.0.1:9180/apisix/admin/upstreams/1" -X PUT -d '
{
  "name": "Conferences API upstream",
  "desc": "Register Conferences API as the upstream",
  "type": "roundrobin",
  "scheme": "https",
  "nodes": {
    "conferenceapi.azurewebsites.net:443": 1
  }
}'
```

### **Create a Plugin Config**

Next, we set up new [plugin config](https://apisix.apache.org/docs/apisix/terminology/plugin-config/) object. We will use 3 plugins [openid-connect](https://apisix.apache.org/docs/apisix/plugins/openid-connect/), [serverless-pre-function](https://apisix.apache.org/docs/apisix/plugins/serverless/) and [proxy-rewrite](https://apisix.apache.org/docs/apisix/plugins/proxy-rewrite/) respectively as we discussed use cases of each plugin earlier. You need replace only `openid-connect` plugin attributes (*ClienID, Secret, Discovery and Introspection endpoints*) with your own Okta details before you execute the curl command.

```bash
curl "http://127.0.0.1:9180/apisix/admin/plugin_configs/1" -X PUT -d ' 
{
    "plugins": {
        "openid-connect":{
            "client_id":"{YOUR_OKTA_CLIENT_ID}",
            "client_secret":"{YOUR_OKTA_CLIENT_SECRET}",
            "discovery":"https://{YOUR_OKTA_ISSUER}/oauth2/default/.well-known/openid-configuration",
            "scope":"openid",
            "bearer_only":true,
            "realm":"master",
            "introspection_endpoint_auth_method":"https://{YOUR_OKTA_ISSUER}/oauth2/v1/introspect",
            "redirect_uri":"https://conferenceapi.azurewebsites.net/"
        },
        "proxy-rewrite": {
            "uri": "/speaker/$http_speakerId/sessions",
            "host":"conferenceapi.azurewebsites.net"
        },
        "serverless-pre-function": {
            "phase": "rewrite",
            "functions" : ["return function(conf, ctx)

    -- Import neccessary libraries
    local core = require(\"apisix.core\")
    local jwt = require(\"resty.jwt\")

    -- Retrieve the JWT token from the Authorization header
    local jwt_token = core.request.header(ctx, \"Authorization\")
    if jwt_token ~= nil then
        -- Remove the Bearer prefix from the JWT token
        local _, _, jwt_token_only = string.find(jwt_token, \"Bearer%s+(.+)\")
        if jwt_token_only ~= nil then
           -- Decode the JWT token
           local jwt_obj = jwt:load_jwt(jwt_token_only)

           if jwt_obj.valid then
             -- Retrieve the value of the speakerId claim from the JWT token
             local speakerId_claim_value = jwt_obj.payload.speakerId

             -- Store the speakerId claim value in the header variable
             core.request.set_header(ctx, \"speakerId\", speakerId_claim_value)
           end
         end
     end
   end
    "]}
    }
}'
```

In the above config, the hardest part to understand can be the custom function code we wrote in Lua inside `serverless-pre-function` plugin:

```lua
return function(conf, ctx)
    -- Import neccessary libraries
    local core = require(\"apisix.core\")
    local jwt = require(\"resty.jwt\")

    -- Retrieve the JWT token from the Authorization header
    local jwt_token = core.request.header(ctx, \"Authorization\")
    if jwt_token ~= nil then
        -- Remove the Bearer prefix from the JWT token
        local _, _, jwt_token_only = string.find(jwt_token, \"Bearer%s+(.+)\")
        if jwt_token_only ~= nil then
           -- Decode the JWT token
           local jwt_obj = jwt:load_jwt(jwt_token_only)

           if jwt_obj.valid then
             -- Retrieve the value of the speakerId claim from the JWT token
             local speakerId_claim_value = jwt_obj.payload.speakerId

             -- Store the speakerId claim value in the header variable
             core.request.set_header(ctx, \"speakerId\", speakerId_claim_value)
           end
         end
   end
end
```

Basically, this plugin will be executed before other two plugins and it does the following:

1. Retrieves the JWT token from the Authorization header.
2. Removes the "Bearer " prefix from the JWT token.
3. Decodes the JWT token using the resty.jwt library.
4. Retrieves the value of the "speakerId" claim from the decoded JWT token.
5. Finally, it stores the value of the "speakerId" claim in the speakerId header variable.

### Configure a new Route

This step involves setting up a new route that uses the plugin config, and configuring the route to work with the upstream (by referencing their IDs) we created in the previous steps:

```bash
curl "http://127.0.0.1:9180/apisix/admin/routes/1"  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "name":"Conferences API speaker sessions route",
    "desc":"Create a new route in APISIX for the Conferences API speaker sessions",
    "methods": ["GET"],
    "uri": "/sessions",
    "upstream_id":"1",
    "plugin_config_id":1
}'
```

In the above configuration, we defined the route matching rules such as only HTTP GET requests to URI `/sessions` will be routed to the correct backend service.

### Obtain a token from Okta

After configuring the upstream, plugins and route on the APISIX side, now we request a token from Okta that contains our `speakerId` custom claim. You can follow the guide that includes information on [building a URL to request a token](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/#request-a-token-that-contains-the-custom-claim) with Okta or simply use the below resulting URL with your Okta issuer and client id:

```bash
https://{YOUR_OKTA_ISSUER}/oauth2/default/v1/authorize?client_id={YOUR_OKTA_CLIENT_ID}
&response_type=id_token
&scope=openid
&redirect_uri=https%3A%2F%2Fconferenceapi.azurewebsites.net
&state=myState
&nonce=myNonceValue
```

After you paste the request into your browser, the browser is redirected to the sign-in page for your Okta and generates *ID Token.*

```bash
https://conferenceapi.azurewebsites.net/#id_token={TOKEN_WILL_BE_HERE}
```

> Note that the process for retrieving a token can be different with other identity providers.
>

### Test the dynamic routing

Finally, now we can verify that the request is being routed to the correct URI path (with speaker specific sessions) based on the matching criteria and JWT token claim by running another simple curl command:

```bash
curl -i -X "GET [http://127.0.0.1:9080/sessions](http://127.0.0.1:9080/sessions)" -H "Authorization: Bearer {YOUR_OKTA_JWT_TOKEN}"
```

Here we go, the outcome as we expected. If we set speakerId to 1 in the Okta JWT claim, Apisix routed the request to the relevant URI path and returned all sessions of this speaker in the response.

```bash
{
  "collection": {
    "version": "1.0",
    "links": [],
    "items": [
      {
        "href": "https://conferenceapi.azurewebsites.net/session/114",
        "data": [
          {
            "name": "Title",
            "value": "\r\n\t\t\tIntroduction to Windows Azure Part I\r\n\t\t"
          },
          {
            "name": "Timeslot",
            "value": "04 December 2013 13:40 - 14:40"
          },
          {
            "name": "Speaker",
            "value": "Scott Guthrie"
          }
        ],
        "links": [
          {
            "rel": "http://tavis.net/rels/speaker",
            "href": "https://conferenceapi.azurewebsites.net/speaker/1"
          },
          {
            "rel": "http://tavis.net/rels/topics",
            "href": "https://conferenceapi.azurewebsites.net/session/114/topics"
          }
        ]
      },
      {
        "href": "https://conferenceapi.azurewebsites.net/session/121",
        "data": [
          {
            "name": "Title",
            "value": "\r\n\t\t\tIntroduction to Windows Azure Part II\r\n\t\t"
          },
          {
            "name": "Timeslot",
            "value": "04 December 2013 15:00 - 16:00"
          },
          {
            "name": "Speaker",
            "value": "Scott Guthrie"
          }
        ],
```
