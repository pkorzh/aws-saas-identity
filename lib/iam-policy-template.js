export const cognitoTrustPolicyTemplate = ({ identityPoolId }) => ({
	Version: '2012-10-17',
	Statement: [
		{
			Effect: 'Allow',
			Principal: {
				Federated: 'cognito-identity.amazonaws.com',
			},
			Action: 'sts:AssumeRoleWithWebIdentity',
			Condition: {
				StringEquals: {
					'cognito-identity.amazonaws.com:aud': identityPoolId,
				},
				'ForAnyValue:StringLike': {
					'cognito-identity.amazonaws.com:amr': 'authenticated',
				},
			},
		},
	],
});

export const tenantUserPolicyTemplate = ({
	cognitoUserPoolArn,
	tenantId,
	bucketName,
}) => ({
	Version: '2012-10-17',
	Statement: [
		{
			Sid: 'S3',
			Effect: 'Allow',
			Action: ['s3:*'],
			Resource: [`arn:aws:s3:::${bucketName}/${tenantId}/*`],
		},
	],
});

export const tenantAdminPolicyTemplate = ({ cognitoUserPoolArn }) => ({
	Version: '2012-10-17',
	Statement: [
		{
			Sid: 'TenantAdminCognitoAccess',
			Effect: 'Allow',
			Action: [
				'cognito-idp:AdminCreateUser',
				'cognito-idp:AdminDeleteUser',
				'cognito-idp:AdminDisableUser',
				'cognito-idp:AdminEnableUser',
				'cognito-idp:AdminGetUser',
				'cognito-idp:ListUsers',
				'cognito-idp:AdminUpdateUserAttributes',
			],
			Resource: [cognitoUserPoolArn],
		},
	],
});
