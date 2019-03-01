import AWSResources from './lib/aws-resources';

const aws = new AWSResources({
	region: 'eu-west-1',
	accountId: '964667303639',
});

export default function({
	tenantId,
	userPoolId,
	user: { username, email, firstName, lastName, role = 'TenantUser' },
}) {
	return aws.createCognitoUser({
		user: {
			username,
			email,
			firstName,
			lastName,
			role,
		},
		userPoolId,
		tenantId,
	});
}
