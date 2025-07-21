import jwt from 'jsonwebtoken';

// By default, API Gateway authorizations are cached (TTL) for 300 seconds.
// This policy will authorize all requests to the same API Gateway instance where the
// request is coming from, thus being efficient and optimising costs.
const generatePolicy = (principalId, methodArn) => {
  const apiGatewayWildcard = methodArn.split('/', 2).join('/') + '/*';

  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: apiGatewayWildcard,
        },
      ],
    },
  };
};

export async function handler(event, context) {
  const tokenHeader = event.headers.authorization || event.headers.Authorization;

  if (!tokenHeader) {
    console.log('event: ', event);
    console.log('Authorization header not found');
    throw 'Unauthorized';
  }

  const token = tokenHeader.replace('Bearer ', '');

  try {
    const claims = jwt.verify(token, process.env.AUTH0_PUBLIC_KEY);
    const policy = generatePolicy(claims.sub, event.routeArn);

    return {
      ...policy,
      context: claims
    };
  } catch (error) {
    console.log(error);
    throw 'Unauthorized';
  }
};
