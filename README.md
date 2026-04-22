# Configuring the Futurae Authenticator

To use the Futurae authenticator with WSO2 Identity Server, you first need to deploy the authenticator and configure it via the WSO2 IS Console. See the instructions below on how to configure the Futurae authenticator with WSO2 Identity Server.

To test the authentication flow, the user must have an account in Futurae and must have the Futurae mobile app installed and a device enrolled. The authenticator supports both enrolling a new device at login time (via QR code) and authenticating with an already-enrolled device using a push approval.

## Prerequisites

- A running WSO2 Identity Server instance (7.0 or above recommended).
- A configured Futurae service with at least one application. Obtain the following from the Futurae Admin Portal:
  - **Service Hostname** — the hostname of the Futurae service (e.g. `api.futurae.com`).
  - **Service ID** — the unique ID of your Futurae service.
  - **Auth API Key** — the authentication API key for your Futurae service.
- A Futurae user account and a mobile device with the Futurae app installed for end-to-end testing.

## Setting Up and Installing the Futurae Connector

**Step 1: Extract the project artifacts**

1. Clone the `wso2-futurae-custom-authenticator` repository.
2. Build the project from the root directory:
   ```bash
   mvn clean install
   ```

**Step 2: Deploy the Futurae Authenticator**

1. Navigate to `components/org.wso2.custom.authenticator.futurae/target`.
2. Copy the `org.wso2.custom.authenticator.futurae-1.0-SNAPSHOT.jar` file.
3. Navigate to `<IS_HOME>/repository/components/dropins` and paste the `.jar` file.
4. Navigate to `components/org.wso2.custom.authenticator.futurae.common/target`.
5. Copy the `org.wso2.custom.authenticator.futurae.common-1.0-SNAPSHOT.jar` file.
6. Navigate to `<IS_HOME>/repository/components/lib` and paste the `.jar` file.
7. Navigate to `components/org.wso2.custom.authenticator.futurae/src/main/resources` and copy the `futurae` directory.
8. Paste it into `<IS_HOME>/repository/resources/identity/extensions/connections`.

**Step 3: Deploy the Futurae REST API**

1. Navigate to `components/org.wso2.custom.authenticator.futurae.rest/org.wso2.custom.authenticator.futurae.rest.dispatcher/target`.
2. Copy the `api#futurae.war` file.
3. Navigate to `<IS_HOME>/repository/deployment/server/webapps` and paste the `.war` file.
4. Open `<IS_HOME>/repository/conf/deployment.toml` and add the following configuration:
   ```toml
   [[resource.access_control]]
    context = "(.*)/api/futurae/v1/authentication/status/(.*)"
    secure = "false"
    http_method = "GET"
    
    [tenant_context]
    enable_tenant_qualified_urls = "true"
    enable_tenanted_sessions = "true"
    rewrite.custom_webapps=["/api/futurae/"]
   ```
   This allows the login page to poll the authentication status endpoint without requiring a session token.

**Step 4: Deploy the login page**

1. Navigate to `components/org.wso2.custom.authenticator.futurae/src/main/resources`.
2. Copy the `futuraelogin.jsp` file.
3. Paste it into `<IS_HOME>/repository/deployment/server/webapps/authenticationendpoint`.

**Step 5: Add i18n resource bundle entries**

The authenticator uses custom i18n keys for its login page. These must be merged into the authentication endpoint's resource bundle.

1. Navigate to `components/org.wso2.custom.authenticator.futurae/src/main/resources`.
2. Open `Resources.properties` and append all entries to:
   ```
   <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/WEB-INF/classes/org/wso2/carbon/identity/application/authentication/endpoint/i18n/Resources.properties
   ```
3. If German locale support is required, open `Resources_de_DE.properties` and append all entries to:
   ```
   <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/WEB-INF/classes/org/wso2/carbon/identity/application/authentication/endpoint/i18n/Resources_de_DE.properties
   ```

**Step 6: Add the Futurae User ID claim**

The authenticator stores the Futurae user ID against the WSO2 user profile using a custom claim. Create this claim in the WSO2 IS Console before testing:

- **Claim URI:** `http://wso2.org/claims/futuraeUserId`
- **Display Name:** Futurae User ID
- **Mapped Attribute:** Choose an appropriate LDAP/AD attribute (e.g. `futuraeUserId`).

## Configuring the Futurae Connection in WSO2 IS Console

After deploying the connector, restart WSO2 IS and navigate to the Console.

1. Go to **Connections** and click **New Connection**.
2. Select **Futurae** from the connection templates.
3. Enter the following values and click **Create**:

### Service Hostname
The hostname of the Futurae service — the host part of the Service Base URL provided by Futurae.

Example:
```
api.futurae.com
```

### Service ID
The Service ID of your Futurae service, available in the Futurae Admin Portal.

Example:
```
<your-futurae-service-id>
```

### Auth API Key
The Auth API Key for your Futurae service. This key is used to sign API requests to Futurae via HMAC-SHA256.

Example:
```
<your-futurae-auth-api-key>
```

Follow these steps to obtain the Auth API Key from the Futurae Admin Portal:
1. Log in to the Futurae Admin Portal.
2. Navigate to your service and open **Settings**.
3. Under **API Keys**, locate or generate the **Auth API Key**.

## The Futurae Authentication Flow

The Futurae authenticator supports two flows depending on whether the user already has a Futurae device enrolled:

### Authentication Flow (device already enrolled)

1. The user completes first-factor login (username/password).
2. WSO2 IS invokes the Futurae authenticator as a second factor.
3. The authenticator calls the Futurae pre-auth API to verify the user exists in Futurae and has an enrolled device.
4. The authenticator initiates a push authentication request via the Futurae API.
5. The user is redirected to the Futurae login page, which polls for the authentication result.
6. The user approves the request in the Futurae mobile app.
7. The login page receives a `COMPLETED` status and submits the completion form.
8. WSO2 IS marks the authentication as successful.

### Enrollment Flow (no device enrolled)

1. The user completes first-factor login.
2. The authenticator detects no enrolled Futurae device for the user.
3. An enrollment request is initiated via the Futurae API and a QR code URL is returned.
4. The user is redirected to the Futurae login page, which displays the QR code and polls for enrollment completion.
5. The user scans the QR code with the Futurae mobile app.
6. The login page receives an `ENROLLMENT_COMPLETED` status, stops polling, and submits the enrollment completion form.
7. The authenticator records the Futurae user ID against the user's WSO2 profile and proceeds to the authentication flow above.

## Adding Futurae as an MFA Step

Once the connection is configured:

1. In the WSO2 IS Console, navigate to **Applications** and select your application.
2. Open the **Login Flow** tab.
3. Add a new step and click **Add Sign In Option**.
4. Select the Futurae connection created above.
5. Save the login flow.
