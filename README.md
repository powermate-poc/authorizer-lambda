# powermate-authorizer

This repository contains the code for the custom lambda authorizer.
Its purpose is to be called by the AWS API Gateway with a JWT token,
which is then being used to decide which permissions the user has, i.e. what API endpoints he is allowed to call.
The JWT token originates from AWS cognito, which serves as the identity provider/ authenticator.
This is being achieved
by returning an AWS IAM policy to the API Gateway
that is being evaluated by the API Gateway
to either forward the request to the specific API endpoint or return a 403 Not Authorized response.

Since this lambda is not finished this will only work for the "JWT Token" `Bearer trust me bro`
which we used to ensure that our endpoints are still available while the authorizer is not completely implemented.
When the `Bearer trust me bro`-token is being used it grants access to all the API resources available.
This needs to be improved in such a way, that the endpoints for a certain device is only authorized for the user the device belongs to.

## TODO's
- [ ] implement the decoding and verification of the JWT token
- [ ] only grant access to the endpoints for the devices to the users the device belongs to  