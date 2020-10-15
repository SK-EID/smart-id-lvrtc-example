# Smart-ID java client and LVRTC Sign API example

This is a simple example how to use [smart-id-java-client](https://github.com/SK-EID/smart-id-java-client) together with [LVRTC Sign API](https://www.eparaksts.lv/en/for_developers/Signing_Platform)

# Usage flow
![Usage flow](images/eparaksts-smart-id-flow.png?raw=true "Usage flow")

# Configuration

LVRTC Sign API parameters for testing
```
API_SERVER = "https://eidas-demo.eparaksts.lv/trustedx-authserver/oauth/lvrtc-eipsign-as/token";
SIGNAPI_SERVER = "https://signapi-prep.eparaksts.lv/";
CLIENT_ID = "";
CLIENT_SECRET = "";
AUTHCERT = "";
```

Smart-ID java client parameters for testing
```
RelyingPartyUUID("00000000-0000-0000-0000-000000000000");
RelyingPartyName("DEMO");
HostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
```
*smart-id-java-client* usage examples [here](https://github.com/SK-EID/smart-id-java-client/wiki/Examples-of-using-it)

# License
This project is licensed under the terms of the [MIT license](LICENSE).
