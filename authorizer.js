'use strict';
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const COGNITO_USERPOOL_ID = process.env.COGNITO_USERPOOL_ID;
const COGNITO_WEB_CLIENT_ID = process.env.COGNITO_WEB_CLIENT_ID;
const jwtVerifier = CognitoJwtVerifier.create({
    userPoolId: COGNITO_USERPOOL_ID,
    tokenUse: "id",
    clientId: COGNITO_WEB_CLIENT_ID
  })
const generatePolicy = (principalId, effect, resource) => {
    let authResponse = {};
    authResponse.principalId = principalId;
    authResponse.context = {
        foo: 'bar'
    };
    if (effect && resource) {
        let policyDocument = {
            Version: "2012-10-17",
            Statement: [
                {
                    Effect: effect,
                    Resource: resource,
                    Action: "execute-api:Invoke",
                },
            ],
        };
        authResponse.policyDocument = policyDocument
    }
    console.log(JSON.stringify(authResponse));
    return authResponse;
}

exports.handler = async (event, context, cb) => {
    const token = event.authorizationToken;
    console.log(token);
    try{
     let payload = await jwtVerifier.verify(token);
     console.log(JSON.stringify(payload));
     cb(null, generatePolicy("user", "allow", event.methodArn))
    }catch(err){
        callback("Error: Invalid token");
    }
    // switch (token) {
    //     case "allow":
    //         cb(null, generatePolicy("user", "allow", event.methodArn))
    //     case "deny":
    //         cb(null, generatePolicy("user", "deny", event.methodArn))
    //     default:
    //         cb("Error - invalid token !!!")
    //}
};