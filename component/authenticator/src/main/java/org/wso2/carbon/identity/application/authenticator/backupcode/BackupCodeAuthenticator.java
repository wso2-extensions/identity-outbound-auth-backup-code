/*
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.org).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.backupcode;

import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SESSION_DATA_KEY;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATION;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.CODE_MISMATCH;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.ACCOUNT_LOCKED_REASON_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODE_FAILED_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants. DISPLAY_BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_ACCESS_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_TRIGGERING_EVENT;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_UPDATING_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.INVALID_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.INVALID_FEDERATED_USER_AUTHENTICATION;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_AUTHENTICATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_FEDERATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_GETTING_THE_USER_STORE_MANAGER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LogConstants.ActionIDs.INITIATE_BACKUP_CODE_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LogConstants.BACKUP_CODE_AUTH_SERVICE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.SUPER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;

/**
 * Backup code authenticator
 */
public class BackupCodeAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(BackupCodeAuthenticator.class);

    private static final String BACKUP_CODE_SEPARATOR = ",";
    private static final String AUTHENTICATOR_BACKUP_CODE = "authenticator.backup.code";
    private static final String BACKUP_CODE_PARAM = "backup.code.param";

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (request.getParameter(BACKUP_CODE) == null) {
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(AUTHENTICATION).equals(BACKUP_CODE_AUTHENTICATOR_NAME)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        String token = httpServletRequest.getParameter(BACKUP_CODE);
        boolean canHandle = StringUtils.isNotBlank(token);
        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BACKUP_CODE_AUTH_SERVICE, FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("Backup-code authenticator handling the authentication.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    /**
     * Check whether status of retrying authentication.
     *
     * @return true, if retry authentication is enabled
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(SESSION_DATA_KEY);
    }

    @Override
    public String getName() {

        return BACKUP_CODE_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BACKUP_CODE_AUTH_SERVICE, INITIATE_BACKUP_CODE_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating backup code authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String username = null;
        String tenantDomain = context.getLoginTenantDomain();
        context.setProperty(AUTHENTICATION, BACKUP_CODE_AUTHENTICATOR_NAME);
        if (!tenantDomain.equals(SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
        }
        AuthenticatedUser authenticatedUserFromContext = BackupCodeUtil.getAuthenticatedUser(context);
        if (authenticatedUserFromContext == null) {
            throw new AuthenticationFailedException(ERROR_NO_AUTHENTICATED_USER.getCode(),
                    ERROR_NO_AUTHENTICATED_USER.getMessage());
        }

        /*
         * The username that the server is using to identify the user, is needed to be identified, as
         * for the federated users, the username in the authentication context may not be same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);

        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);

        try {
            AuthenticatedUser authenticatingUser =
                    resolveAuthenticatingUser(context, authenticatedUserFromContext, mappedLocalUsername, tenantDomain,
                            isInitialFederationAttempt);
            username = UserCoreUtil.addTenantDomainToEntry(authenticatingUser.getUserName(), tenantDomain);
            context.setProperty(AUTHENTICATED_USER, authenticatingUser);

            String retryParam = StringUtils.EMPTY;
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }
            Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
            boolean showAuthFailureReason = Boolean.parseBoolean(parameterMap.get(
                    FrameworkConstants.SHOW_AUTHFAILURE_RESON_CONFIG));
            boolean showAuthFailureReasonOnLoginPage = false;
            if (showAuthFailureReason) {
                showAuthFailureReasonOnLoginPage = Boolean.parseBoolean(
                        parameterMap.get(FrameworkConstants.SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE_CONF));
            }
            String errorParam = StringUtils.EMPTY;
            if (showAuthFailureReason) {
                errorParam = getErrorParamsStringFromErrorContext();
            }
            boolean isBackupCodesExistForUser = false;

            // Not required to check the backup code enable state for the initial login of the federated users.
            if (!isInitialFederationAttempt) {
                isBackupCodesExistForUser = isBackupCodesExistForUser(
                        UserCoreUtil.addDomainToName(username, authenticatingUser.getUserStoreDomain()));
            }
            if (isBackupCodesExistForUser) {
                if (log.isDebugEnabled()) {
                    log.debug("Backup codes exists for the user: " + username);
                }
            }

            /*
             * This multi option URI is used to navigate back to multi option page to select a different
             * authentication option from backup code pages.
             */
            String multiOptionURI = BackupCodeUtil.getMultiOptionURIQueryParam(request);
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(BACKUP_CODE_AUTH_SERVICE,
                        INITIATE_BACKUP_CODE_REQUEST);
                diagnosticLogBuilder.inputParams(getApplicationDetails(context))
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParam("backup code exists for user", isBackupCodesExistForUser);
                addUserDetailsToDiagnosticLog(diagnosticLogBuilder, authenticatingUser);
            }
            if (isBackupCodesExistForUser) {
                // If backup code is enabled for the user.
                if (!showAuthFailureReasonOnLoginPage) {
                    errorParam = StringUtils.EMPTY;
                }
                String backupCodeLoginPageUrl =
                        buildBackupCodeLoginPageURL(context, username, retryParam, errorParam, multiOptionURI);
                response.sendRedirect(backupCodeLoginPageUrl);
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .resultMessage("Redirecting to backup code login page.")
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            } else {
                String backupCodeErrorPageUrl =
                        buildBackupCodeErrorPageURL(context, username, retryParam, errorParam, multiOptionURI);
                response.sendRedirect(backupCodeErrorPageUrl);
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.FAILED)
                            .resultMessage("Redirecting to backup code error page.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    "Error when redirecting the backup code login response, user : " + username, e);
        } catch (BackupCodeException e) {
            throw new AuthenticationFailedException(
                    "Error when checking backup code enabled for the user : " + username, e);
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot get the username from first step.",
                    e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building backup code page URL.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String token = request.getParameter(BACKUP_CODE);
        AuthenticatedUser authenticatingUser = (AuthenticatedUser) context.getProperty(AUTHENTICATED_USER);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BACKUP_CODE_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing backup code authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            addUserDetailsToDiagnosticLog(diagnosticLogBuilder, authenticatingUser);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        String username = authenticatingUser.toFullQualifiedUsername();
        validateAccountLockStatusForLocalUser(context, username);

        if (StringUtils.isBlank(token)) {
            try {
                handleBackupCodeVerificationFail(authenticatingUser);
            } catch (BackupCodeException e) {
                throw new AuthenticationFailedException(e.getMessage());
            }
            throw new AuthenticationFailedException(
                    "Empty Backup code in the request. Authentication Failed for user: " + username);
        }
        try {
            String backupCodes;
            if (isInitialFederationAttempt(context)) {
                backupCodes = backupCodesForFederatedUser(context);
                if (!isValidBackupCode(token, context, username, backupCodes)) {
                    throw new AuthenticationFailedException(
                            "Invalid Token. Authentication failed for federated user: " + username);
                }
            } else {
                backupCodes = backupCodesForLocalUser(username);
                if (!isValidBackupCode(token, context, username, backupCodes)) {
                    handleBackupCodeVerificationFail(authenticatingUser);
                    throw new AuthenticationFailedException(
                            "Invalid Token. Authentication failed, user :  " + username);
                }
            }
            // Removing used backup code from the list.
            removeUsedBackupCode(token, username, backupCodes);
            if (StringUtils.isNotBlank(username)) {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setAuthenticatedSubjectIdentifier(username);
                authenticatedUser.setUserName(
                        UserCoreUtil.removeDomainFromName(MultitenantUtils.getTenantAwareUsername(username)));
                authenticatedUser.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
                authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(username));
                context.setSubject(authenticatedUser);
            } else {
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
            }
        } catch (BackupCodeException e) {
            throw new AuthenticationFailedException("Backup code Authentication process failed for user " + username,
                    e);
        }
        // It reached here means the authentication was successful.
        try {
            resetBackupCodeFailedAttempts(authenticatingUser);
        } catch (BackupCodeException e) {
            throw new AuthenticationFailedException("Error occurred while resetting account lock claim");
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BACKUP_CODE_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Backup code authentication successful.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            addUserDetailsToDiagnosticLog(diagnosticLogBuilder, authenticatingUser);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private boolean isJitProvisioningEnabled(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return false;
        }
        return provisioningConfig.isProvisioningEnabled();
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            IdentityProvider idp = BackupCodeDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw new AuthenticationFailedException(
                        String.format(INVALID_FEDERATED_AUTHENTICATOR.getMessage(), idpName, tenantDomain));
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(
                    String.format(INVALID_FEDERATED_AUTHENTICATOR.getMessage(), idpName, tenantDomain));
        }
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username.
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }

        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw new AuthenticationFailedException(ERROR_NO_FEDERATED_USER.getCode(),
                    ERROR_NO_FEDERATED_USER.getMessage());
        }
        String associatedLocalUsername = FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(
                MultitenantUtils.getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param context                    Authentication context.
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticationContext context,
                                                        AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername, String tenantDomain,
                                                        boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }

        if (!isJitProvisioningEnabled(authenticatedUserInContext, tenantDomain)) {
            throw new AuthenticationFailedException(INVALID_FEDERATED_USER_AUTHENTICATION.getCode(),
                    INVALID_FEDERATED_USER_AUTHENTICATION.getMessage());
        }

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            context.setProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT, true);
            return authenticatedUserInContext;
        }

        /*
         * At this point, the authenticating user is in our system but can have a different mapped username compared to the
         * identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
         * with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting user store: %s as the provisioning user store for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    /**
     * Check whether backup code is enabled for local user or not.
     *
     * @param username Username of the user.
     * @return true, if backup code enable for local user.
     * @throws BackupCodeException when user realm is null or could not find user.
     */
    private boolean isBackupCodesExistForUser(String username)
            throws BackupCodeException, AuthenticationFailedException {

        String tenantAwareUsername = null;
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            Map<String, String> UserClaimValues = BackupCodeUtil.getUserStoreManagerOfUser(username)
                    .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
            String encryptedBackupCodes = UserClaimValues.get(BACKUP_CODES_CLAIM);
            return StringUtils.isNotBlank(encryptedBackupCodes);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_GETTING_THE_USER_STORE_MANAGER.getCode(),
                    String.format(ERROR_GETTING_THE_USER_STORE_MANAGER.getMessage(), tenantAwareUsername, e));
        }
    }

    private String buildBackupCodeLoginPageURL(AuthenticationContext context, String username, String retryParam,
                                               String errorParam, String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        Map<String, String> queryParams = extractQueryParamsFromContext(context);
        String queryString = "sessionDataKey=" + context.getContextIdentifier() + "&authenticators=" + getName() +
                "&type=backup-code" + retryParam + "&username=" + username + errorParam;

        if (queryParams.containsKey("t")) {
            queryString = queryString + "&t=" + queryParams.get("t");
        }

        if (queryParams.containsKey("sp")) {
            queryString = queryString + "&sp=" + queryParams.get("sp");
        }

        queryString = queryString + multiOptionURI;
        String loginPage = FrameworkUtils.appendQueryParamsStringToUrl(BackupCodeUtil.getBackupCodeLoginPage(context),
                queryString);
        return buildAbsoluteURL(loginPage);
    }

    private Map<String, String> extractQueryParamsFromContext(AuthenticationContext context) {

        Map<String, String> parameters = new HashMap<>();
        String[] keyValuePairs = context.getQueryParams().split("&");
        for (String pair : keyValuePairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                parameters.put(keyValue[0], keyValue[1]);
            }
        }
        return parameters;
    }

    private String buildErrorParamString(Map<String, String> paramMap) {

        StringBuilder params = new StringBuilder();
        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            params.append("&").append(entry.getKey()).append("=").append(entry.getValue());
        }
        return params.toString();
    }

    private String getErrorParamsStringFromErrorContext() {

        String errorParam = StringUtils.EMPTY;
        IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
        IdentityUtil.clearIdentityErrorMsg();
        if (errorContext != null) {
            log.debug("Identity error message context is not null.");
            String errorCode = errorContext.getErrorCode();
            String reason = null;
            if (StringUtils.isNotBlank(errorCode)) {
                String[] errorCodeWithReason = errorCode.split(":", 2);
                errorCode = errorCodeWithReason[0];
                if (errorCodeWithReason.length > 1) {
                    reason = errorCodeWithReason[1];
                }
                if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                    Map<String, String> paramMap = new HashMap<>();
                    paramMap.put(FrameworkConstants.ERROR_CODE, errorCode);
                    if (StringUtils.isNotBlank(reason)) {
                        paramMap.put(FrameworkConstants.LOCK_REASON, reason);
                    } else if (errorContext.getFailedLoginAttempts() == errorContext.getMaximumLoginAttempts()) {
                        // The account just got locked because of max attempts reached.
                        paramMap.put(FrameworkConstants.LOCK_REASON,
                                BackupCodeAuthenticatorConstants.MAX_ATTEMPTS_EXCEEDED);
                    }
                    errorParam = buildErrorParamString(paramMap);
                }
            }
        }
        return errorParam;
    }

    private String buildAbsoluteURL(String redirectUrl) throws URISyntaxException, URLBuilderException {

        URI uri = new URI(redirectUrl);
        if (uri.isAbsolute()) {
            return redirectUrl;
        } else {
            return ServiceURLBuilder.create().addPath(redirectUrl).build().getAbsolutePublicURL();
        }
    }

    private String buildBackupCodeErrorPageURL(AuthenticationContext context, String username, String retryParam,
                                               String errorParam, String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "sessionDataKey=" + context.getContextIdentifier() + "&authenticators=" + getName() +
                "&type=backup_code_error" + retryParam + "&username=" + username + errorParam + multiOptionURI;
        String errorPage = FrameworkUtils.appendQueryParamsStringToUrl(BackupCodeUtil.getBackupCodeErrorPage(context),
                queryString);
        return buildAbsoluteURL(errorPage);
    }

    private void validateAccountLockStatusForLocalUser(AuthenticationContext context, String username)
            throws AuthenticationFailedException {

        boolean isLocalUser = BackupCodeUtil.isLocalUser(context);
        AuthenticatedUser authenticatedUserObject = (AuthenticatedUser) context.getProperty(AUTHENTICATED_USER);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        if (isLocalUser &&
                BackupCodeUtil.isAccountLocked(authenticatedUserObject.getUserName(), tenantDomain, userStoreDomain)) {
            setErrorContextWhenAccountLocked(username);
            String errorMessage =
                    String.format("Authentication failed since authenticated user: %s, account is locked.",
                            getUserStoreAppendedName(username));
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new AuthenticationFailedException(errorMessage);
        }
    }

    private void setErrorContextWhenAccountLocked(String username) throws AuthenticationFailedException {

        String accountLockedReason = StringUtils.EMPTY;
        String tenantAwareUsername;
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            Map<String, String> UserClaimValues = BackupCodeUtil.getUserStoreManagerOfUser(username)
                    .getUserClaimValues(tenantAwareUsername, new String[]{ACCOUNT_LOCKED_REASON_CLAIM}, null);
            if (UserClaimValues != null) {
                accountLockedReason = UserClaimValues.get(ACCOUNT_LOCKED_REASON_CLAIM);
            }
        }
        catch (UserStoreException | BackupCodeException e) {
            throw new AuthenticationFailedException(
                    "Could not get the account locked reason. Authentication Failed for user: " + username);
        }
        IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":" + accountLockedReason);
        IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
    }

    private boolean isInitialFederationAttempt(AuthenticationContext context) {

        if (context.getProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT) != null) {
            return Boolean.parseBoolean(context.getProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT).toString());
        }
        return false;
    }

    /**
     * Verify whether a given token is valid for the federated user.
     *
     * @param context Authentication context.
     * @return true if backup code is valid otherwise false.
     */
    private String backupCodesForFederatedUser(AuthenticationContext context) {

        String backupCodes = null;
        if (context.getProperty(BACKUP_CODES_CLAIM) != null) {
            backupCodes = context.getProperty(BACKUP_CODES_CLAIM).toString();
        }
        return backupCodes;
    }

    /**
     * Verify whether a given token is valid for a stored local user.
     *
     * @param username Username of the user.
     * @return true if code is valid otherwise false.
     * @throws BackupCodeException UserRealm for user or tenant domain is null.
     */
    private String backupCodesForLocalUser(String username) throws BackupCodeException {

        String tenantAwareUsername = null;
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            Map<String, String> userClaimValues = BackupCodeUtil.getUserStoreManagerOfUser(username)
                    .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
            return userClaimValues.get(BACKUP_CODES_CLAIM);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), tenantAwareUsername, e));
        }
    }

    private boolean isValidBackupCode(String token, AuthenticationContext context, String userName,
                                      String hashedBackupCodes) throws BackupCodeException {

        if (StringUtils.isBlank(hashedBackupCodes)) {
            if (log.isDebugEnabled()) {
                log.debug("No backup codes found for user: " + userName);
            }
            return false;
        }
        List<String> backupCodeList = new ArrayList<>(Arrays.asList(hashedBackupCodes.split(BACKUP_CODE_SEPARATOR)));
        if (!backupCodeList.contains(BackupCodeUtil.generateHashBackupCode(token))) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Given code: %s does not match with any saved backup codes codes for user: %s",
                        token, userName));
            }
            context.setProperty(CODE_MISMATCH, true);
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Saved backup code found for the user: " + userName);
        }
        return true;
    }

    /**
     * Remove the used code from the saved backup code list for the user.
     *
     * @param code              Backup code given by the user.
     * @param username          Username.
     * @param hashedBackupCodes Existing hashed backup codes in a comma separated string.
     * @throws BackupCodeException If an error occurred while removing the used backup code.
     */
    private void removeUsedBackupCode(String code, String username, String hashedBackupCodes)
            throws BackupCodeException {

        List<String> backupCodeList = new ArrayList<>(Arrays.asList(hashedBackupCodes.split(BACKUP_CODE_SEPARATOR)));

        backupCodeList.remove(BackupCodeUtil.generateHashBackupCode(code));
        String unusedBackupCodes = String.join(BACKUP_CODE_SEPARATOR, backupCodeList);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        try {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Removing used token: %s from the backup code list of user: %s", code,
                        username));
            }
            Map<String, String> claimsToUpdate = new HashMap<>();
            claimsToUpdate.put(BACKUP_CODES_CLAIM, unusedBackupCodes);
            BackupCodeUtil.getUserStoreManagerOfUser(username).setUserClaimValues(tenantAwareUsername, claimsToUpdate, null);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_UPDATING_BACKUP_CODES.getCode(),
                    ERROR_UPDATING_BACKUP_CODES.getMessage(), e);
        }
    }

    /**
     * Reset Backup code Failed Attempts count upon successful completion of the backup code verification. By default,
     * the backup code authenticator will support account lock on failed attempts if the account locking is enabled
     * for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws BackupCodeException If an error occurred while resetting the backup code failed attempts.
     */
    private void resetBackupCodeFailedAttempts(AuthenticatedUser user) throws BackupCodeException {

        UserStoreManager userStoreManager = BackupCodeUtil.getUserStoreManagerOfUser(user.toFullQualifiedUsername());
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, BACKUP_CODE_AUTHENTICATOR_NAME);
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, BACKUP_CODE_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, true);
        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    /**
     * Execute account lock flow for backup code verification failures. By default, the backup code
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws BackupCodeException If an error occurred while resetting the backup code failed attempts.
     */
    private void handleBackupCodeVerificationFail(AuthenticatedUser user) throws BackupCodeException {

        UserStoreManager userStoreManager = BackupCodeUtil.getUserStoreManagerOfUser(user.toFullQualifiedUsername());
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, BACKUP_CODE_AUTHENTICATOR_NAME);
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, BACKUP_CODE_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    /**
     * Trigger event.
     *
     * @param eventName      Event name.
     * @param user           Authenticated user.
     * @param metaProperties Meta details.
     * @throws BackupCodeException If an error occurred while triggering the event.
     */
    private void triggerEvent(String eventName, AuthenticatedUser user, Map<String, Object> metaProperties)
            throws BackupCodeException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        if (metaProperties != null) {
            for (Map.Entry<String, Object> metaProperty : metaProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            BackupCodeDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw new BackupCodeException(ERROR_TRIGGERING_EVENT.getCode(),
                    String.format(ERROR_TRIGGERING_EVENT.getMessage(), eventName, user.getUserName()), e);
        }
    }

    /**
     * Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map with application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * Get the user id from the authenticated user.
     *
     * @param authenticatedUser AuthenticationContext.
     * @return User id.
     */
    private Optional<String> getUserId(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null) {
            return Optional.empty();
        }
        try {
            if (authenticatedUser.getUserId() != null) {
                return Optional.ofNullable(authenticatedUser.getUserId());
            }
        } catch (UserIdNotFoundException e) {
            log.debug("Error while getting the user id from the authenticated user.", e);
        }
        return Optional.empty();
    }

    private void addUserDetailsToDiagnosticLog(DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder,
                                               AuthenticatedUser user) {

        if (user != null) {
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(user.getUserName()) :
                            user.getUserName())
                    .inputParam("user store domain", user.getUserStoreDomain());
            Optional<String> optionalUserId = getUserId(user);
            optionalUserId.ifPresent(userId -> diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID,
                    userId));
        }
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    public String getI18nKey() {

        return BackupCodeAuthenticatorConstants.AUTHENTICATOR_BACKUP_OTP;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        String idpName = null;

        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(AUTHENTICATOR_BACKUP_CODE);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        List<String> requiredParams = new ArrayList<>();

            AuthenticatorParamMetadata codeMetadata = new AuthenticatorParamMetadata(
                    BACKUP_CODE, DISPLAY_BACKUP_CODE, FrameworkConstants.AuthenticatorParamType.STRING,
                    1, Boolean.TRUE, BACKUP_CODE_PARAM);
            authenticatorParamMetadataList.add(codeMetadata);
            requiredParams.add(BACKUP_CODE);

        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        authenticatorData.setRequiredParams(requiredParams);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
        return Optional.of(authenticatorData);
    }
}
