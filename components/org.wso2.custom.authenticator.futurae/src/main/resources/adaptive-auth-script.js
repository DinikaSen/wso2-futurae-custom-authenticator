// Only prompt for email OTP (step 2) if the user does not have a mobile device registered (identified by the existence of a non-empty futuraeID)
function onLoginRequest(context) {
    executeStep(1, {
        onSuccess: function(context) {
            // Extracting authenticated user from the first step.
            // NOTE: May need to change if the first factor is a federated IdP
            var user = context.steps[1].subject;

            // Get futuraeId claim for the user.
            var futuraeId = user.localClaims['http://wso2.org/claims/futuraeUserId'];

            if (futuraeId != null && futuraeId !== undefined && futuraeId.trim() !== '') {
                Log.info("User has a mobile device registered. hence skipping 2nd step");
                executeStep(3);
            }
            else {
                Log.info("User does not have a mobile device registered. hence executing 2nd step and then 3rd step");
                executeStep(2, {
                    onSuccess: function(context) {
                        executeStep(3);
                    }
                });
            }
        }
    });
}