'use strict';

const jwt = require('jsonwebtoken');

const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.auth = (event, context, cb) => {
  if (event.authorizationToken) {
    // remove "bearer " from token
    const token = event.authorizationToken.substring(7);
    const options = {
      audience: AUTH0_CLIENT_ID,
    };
    jwt.verify(token, AUTH0_CLIENT_SECRET, options, (err, decoded) => {
      if (err) {
        cb('Unauthorized');
      } else {
        cb(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
      }
    });
  } else {
    cb('Unauthorized');
  }
};

// public API
module.exports.hello = (event, context, callback) => {
  const response = {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Go Serverless v1.0! Public API says Hi!',
      input: event,
    }),
  };

  callback(null, response);
};

// Private API
module.exports.privateEndpoint = (event, context, cb) => {
  cb(null, { message: 'Only logged in users can see this' });
};
