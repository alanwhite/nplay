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
      issuer: 'https://arw001.eu.auth0.com/',
    };
    console.log(event.authorizationToken);
    console.log(token);
    console.log(options);
    console.log(AUTH0_CLIENT_SECRET);
    jwt.verify(token, AUTH0_CLIENT_SECRET, options, (err, decoded) => {
      if (err) {
        console.log('Error!');
        console.log(err);
        console.log(decoded);
        cb('Unauthorized');
      } else {
        console.log(decoded);
        cb(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
      }
    });
  } else {
    // console.log('no authorizationToken');
    cb('Unauthorized');
  }
};

// public API
module.exports.hello = (event, context, callback) => {
  const response = {
    statusCode: 200,
    headers: {
       "Access-Control-Allow-Origin" : "https://nplay.whiteware.org"
    },
    body: JSON.stringify({
      message: 'Go Serverless v1.0! Public API says Hi!',
      input: event,
    }),
  };

  callback(null, response);
};

// Private API
module.exports.privateEndpoint = (event, context, cb) => {
  const response = {
    statusCode: 200,
    // headers: {
    //    "Access-Control-Allow-Origin" : "*",
    //    "Access-Control-Allow-Credentials" : true
    // },
    headers: {
       "Access-Control-Allow-Origin" : "*"
    },
    body: JSON.stringify({
      message: 'You are a logged in user so you can see this',
      input: event,
    }),
  };


  console.log(event);
  console.log(context);

  console.log(event.headers.Authorization);

  // if (event.authorizationToken) {
  if (event.headers.Authorization) {
    // remove "bearer " from token
    const token = event.headers.Authorization.substring(7);
    const options = {
      audience: AUTH0_CLIENT_ID,
      issuer: 'https://arw001.eu.auth0.com/',
    };

    jwt.verify(token, AUTH0_CLIENT_SECRET, options, (err, decoded) => {
      if (err) {
        console.log('Error!');
        console.log(err);
        console.log(decoded);
        response.statusCode = 401;
        response.body = JSON.stringify({
          message: 'Error validating your login token',
          input: event,
        });
      } else {
        console.log(decoded);
      }

      cb(null, response);

      console.log('will this be seen?');
    });

  } else { // no auth token present
    response.statusCode = 403;
    response.body = JSON.stringify({
      message: 'Nope, not without logging in first',
      input: event,
    });

    cb(null, response);
  }

};
