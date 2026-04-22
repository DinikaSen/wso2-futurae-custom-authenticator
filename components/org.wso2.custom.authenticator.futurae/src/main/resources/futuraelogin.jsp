<%--
  ~ Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com).
  ~
  ~ WSO2 LLC. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied. See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
--%>

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthContextAPIClient" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityCoreConstants" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.EndpointConfigManager" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthenticationEndpointUtil" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.STATUS" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.STATUS_MSG" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.CONFIGURATION_ERROR" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.AUTHENTICATION_MECHANISM_NOT_CONFIGURED" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.ENABLE_AUTHENTICATION_WITH_REST_API" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.ERROR_WHILE_BUILDING_THE_ACCOUNT_RECOVERY_ENDPOINT_URL" %>
<%@ page import="java.nio.charset.Charset" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>
<%@ page import="java.io.File" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.owasp.encoder.Encode" %>

<%@ taglib prefix="layout" uri="org.wso2.identity.apps.taglibs.layout.controller" %>

<%@ include file="includes/localize.jsp" %>
<%@ include file="includes/init-url.jsp" %>

<%-- Branding Preferences --%>
<jsp:directive.include file="includes/branding-preferences.jsp"/>

<% request.setAttribute("pageName", "futuraelogin"); %>

<!doctype html>
<html lang="en-US">
<head>
    <script language="JavaScript" type="text/javascript" src="libs/jquery_3.6.0/jquery-3.6.0.min.js"></script>
    <%-- header --%>
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
    <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
    <jsp:include page="includes/header.jsp"/>
    <% } %>
</head>

<body class="login-portal layout email-otp-portal-layout" data-page="<%= request.getAttribute("pageName") %>">
    <layout:main layoutName="<%= layout %>" layoutFileRelativePath="<%= layoutFileRelativePath %>" data="<%= layoutData %>" >
        <layout:component componentName="ProductHeader">
            <%-- product-title --%>
            <%
                File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
                if (productTitleFile.exists()) {
            %>
                <jsp:include page="extensions/product-title.jsp"/>
            <% } else { %>
                <jsp:include page="includes/product-title.jsp"/>
            <% } %>
        </layout:component>
        <layout:component componentName="MainSection">
            <div class="ui segment">
                <%-- page content --%>
                <h2><%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.heading")%></h2>
                <div class="ui divider hidden"></div>
                <div class="ui visible negative message" style="display: none;" id="error-msg"></div>

                <div class="segment-form">

                    <!-- Authentication in progress -->
                    <div class="align-center" id="inProgressDisplay" style="display:none;">
                        <h5 id="authenticationStatusMessage"></h5>
                    </div>

                    <!-- Proceed Authentication form -->
                    <form id="completeAuthenticationForm" action="<%=commonauthURL%>" method="POST">
                        <input id="sessionDataKeyAuthenticationForm" type="hidden" name="sessionDataKey"
                        value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>' />
                        <input id="authType" name="authType" type="hidden" value="futurae">
                    </form>

                    <!-- Enrollment QR display -->
                    <div class="align-center" id="enrollmentDisplay" style="display:none;">
                        <p id="enrollmentMessage"></p>
                        <img id="enrollmentQrCode" src="" alt="<%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.enrollment.qr.alt")%>"
                             style="max-width:250px; margin:16px auto; display:block;" />
                        <div class="ui divider hidden"></div>
                        <h5 id="enrollmentPollingStatus"></h5>
                    </div>

                    <!-- Proceed Enrollment form -->
                    <form id="completeEnrollmentForm" action="<%=commonauthURL%>" method="POST">
                        <input id="sessionDataKeyAuthenticationForm" type="hidden" name="sessionDataKey"
                        value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>' />
                        <input id="authType" name="authType" type="hidden" value="futurae">
                    </form>
                </div>
            </div>
        </layout:component>
        <layout:component componentName="ProductFooter">
            <%-- product-footer --%>
            <%
                File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
                if (productFooterFile.exists()) {
            %>
                <jsp:include page="extensions/product-footer.jsp"/>
            <% } else { %>
                <jsp:include page="includes/product-footer.jsp"/>
            <% } %>
        </layout:component>
        <layout:dynamicComponent filePathStoringVariableName="pathOfDynamicComponent">
            <jsp:include page="${pathOfDynamicComponent}" />
        </layout:dynamicComponent>
    </layout:main>

    <%-- footer --%>
    <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
    %>
        <jsp:include page="extensions/footer.jsp"/>
    <% } else { %>
        <jsp:include page="includes/footer.jsp"/>
    <% } %>

    <%
        String toEncode = EndpointConfigManager.getAppName() + ":" + String.valueOf(EndpointConfigManager.getAppPassword());
        byte[] encoding = Base64.encodeBase64(toEncode.getBytes());
        String authHeader = new String(encoding, Charset.defaultCharset());
        String header = "Client " + authHeader;
        
        // Resolve error message via resource bundle using the status parameter as the lookup key.
        // Keys follow the pattern "futurae.error.<STATUS>" (e.g. futurae.error.INVALID_USER).
        // Falls back to the generic key when no status-specific entry exists.
        String statusParam = request.getParameter("status");
        String lookupKey = (statusParam != null && !statusParam.trim().isEmpty())
                ? "futurae.error." + statusParam
                : "futurae.error.generic";
        String errorMessage = AuthenticationEndpointUtil.i18n(resourceBundle, lookupKey);
        // If the key is not found, i18n returns the key itself — fall back to the generic message.
        if (lookupKey.equals(errorMessage)) {
            errorMessage = AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.error.generic");
        }

    %>

    <script type="text/javascript">
        var i18n = {
            authInProgress: "<%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.auth.in.progress")%>",
            enrollScanInstructions: "<%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.enrollment.scan.instructions")%>",
            enrollWaiting: "<%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.enrollment.waiting")%>",
            errorTimeout: "<%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.error.timeout")%>",
            errorStatusCheck: "<%=AuthenticationEndpointUtil.i18n(resourceBundle, "futurae.error.status.check")%>"
        };

        var sessionDataKey;
        var refreshInterval = 5000;
        var timeout = 90000;
        var intervalListener;
        var isPollingStopped = false;
        var authStatusCheckApi = "/api/futurae/v1/authentication/status/";

        $(document).ready(function () {
            var urlParams = new URLSearchParams(window.location.search);
            sessionDataKey = urlParams.get('sessionDataKey');

            if (!urlParams.has('status')) return;

            var status = urlParams.get('status');

            if (status === 'PENDING') {
                document.getElementById("inProgressDisplay").style.display = 'block';
                document.getElementById("authenticationStatusMessage").innerText = i18n.authInProgress;
                pollStatus(completeAuthentication);

            } else if (status === 'PENDING_ENROLLMENT') {
                var qrUrl = urlParams.get('enrollmentQrUrl');
                document.getElementById("enrollmentDisplay").style.display = 'block';
                document.getElementById("enrollmentMessage").innerText = i18n.enrollScanInstructions;
                document.getElementById("enrollmentQrCode").src = qrUrl;
                document.getElementById("enrollmentPollingStatus").innerText = i18n.enrollWaiting;
                pollStatus(completeEnrollment);

            } else if (status === 'FAILED' || status === 'FUTURAE_LOGIN_DENIED') {
                handleError('<%= Encode.forHtmlContent(errorMessage) %>');
            }
        });

        function pollStatus(onComplete) {
            var startTime = new Date().getTime();

            intervalListener = window.setInterval(function () {
                if (isPollingStopped) return;

                var now = new Date().getTime();
                if ((startTime + timeout) < now) {
                    isPollingStopped = true;
                    window.clearInterval(intervalListener);
                    handleError(i18n.errorTimeout);
                    return;
                }

                $.ajax("<%= Encode.forJavaScriptBlock(identityServerEndpointContextParam)%>" + authStatusCheckApi + sessionDataKey, {
                    method: 'GET',
                    headers: { "Authorization": "<%=header%>" },
                    success: function (res) {
                        if (["COMPLETED", "ENROLLMENT_COMPLETED", "FUTURAE_LOGIN_DENIED", "FAILED"].includes(res.status)) {
                            if (!isPollingStopped) {
                                isPollingStopped = true;
                                window.clearInterval(intervalListener);
                                onComplete();
                            }
                        }
                    },
                    error: function () {
                        if (!isPollingStopped) {
                            isPollingStopped = true;
                            window.clearInterval(intervalListener);
                            handleError(i18n.errorStatusCheck);
                        }
                    }
                });
            }, refreshInterval);
        }

        function completeAuthentication() {
            document.getElementById("completeAuthenticationForm").submit();
        }

        function completeEnrollment() {
            document.getElementById("completeEnrollmentForm").submit();
        }

        function handleError(msg) {
            document.getElementById("inProgressDisplay").style.display = 'none';
            document.getElementById("enrollmentDisplay").style.display = 'none';
            var errorDiv = document.getElementById("error-msg");
            errorDiv.innerHTML = msg;
            errorDiv.style.display = "block";
        }
    </script>
</body>
</html>
