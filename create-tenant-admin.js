import AWSResources from './lib/aws-resources';

import {
	cognitoTrustPolicyTemplate,
	tenantAdminPolicyTemplate,
	tenantUserPolicyTemplate,
} from './iam-policy-template';

const aws = new AWSResources({
	region: 'eu-west-1',
	accountId: '964667303639',
});

export default async function({
	tenantId,
	user: { username, email, firstName, lastName, role = 'TenantAdmin' },
}) {
	const rollbacks = [];

	try {
		const {
			id: userPoolId,
			rollback: userPoolRollback,
		} = await aws.createUserPool({ name: `${tenantId}` });

		rollbacks.push(userPoolRollback);

		const {
			id: clientId,
			rollback: userPoolClientRollback,
		} = await aws.createUserPoolClient({ name: `${tenantId}`, userPoolId });

		rollbacks.push(userPoolClientRollback);

		const {
			id: identityPoolId,
			rollback: identityPoolRollback,
		} = await aws.createIdentityPool({
			clientId,
			userPoolId,
			name: `${tenantId}`,
		});

		rollbacks.push(identityPoolRollback);

		const trustPolicy = cognitoTrustPolicyTemplate({ identityPoolId });

		const { rollback: createCognitoUserRollback } = await aws.createCognitoUser(
			{
				user: {
					username,
					email,
					firstName,
					lastName,
					role,
				},
				userPoolId,
				tenantId,
			}
		);

		rollbacks.push(createCognitoUserRollback);

		const {
			arn: tenantAdminPolicyArn,
			rollback: tenantAdminPolicyRollback,
		} = await aws.createPolicy({
			name: `tenant-${tenantId}-admin-policy`,
			document: tenantAdminPolicyTemplate({
				cognitoUserPoolArn: `arn:aws:cognito-idp:${aws.region}:${aws.accountId}:userpool/${userPoolId}`,
			}),
		});

		rollbacks.push(tenantAdminPolicyRollback);

		const {
			arn: tenantUserPolicyArn,
			rollback: tenantUserPolicyRollback,
		} = await aws.createPolicy({
			name: `tenant-${tenantId}-user-policy`,
			document: tenantUserPolicyTemplate({
				cognitoUserPoolArn: `arn:aws:cognito-idp:${aws.region}:${aws.accountId}:userpool/${userPoolId}`,
			}),
		});

		rollbacks.push(tenantUserPolicyRollback);

		const {
			arn: tenantAuthenticatedRoleArn,
			rollback: tenantAuthenticatedRoleRollback,
		} = await aws.createRole({
			name: `tenant-${tenantId}-authenticated-role`,
			assumeRolePolicyDocument: trustPolicy,
		});

		rollbacks.push(tenantAuthenticatedRoleRollback);

		const {
			name: tenantAdminRoleName,
			arn: tenantAdminRoleArn,
			rollback: tenantAdminRoleRollback,
		} = await aws.createRole({
			name: `tenant-${tenantId}-admin-role`,
			assumeRolePolicyDocument: trustPolicy,
		});

		rollbacks.push(tenantAdminRoleRollback);

		const {
			name: tenantUserRoleName,
			arn: tenantUserRoleArn,
			rollback: tenantUserRoleRollback,
		} = await aws.createRole({
			name: `tenant-${tenantId}-user-role`,
			assumeRolePolicyDocument: trustPolicy,
		});

		rollbacks.push(tenantUserRoleRollback);

		await aws.addPolicyToRole({
			policyArn: tenantAdminPolicyArn,
			roleName: tenantAdminRoleName,
		});

		await aws.addPolicyToRole({
			policyArn: tenantUserPolicyArn,
			roleName: tenantUserRoleName,
		});

		await aws.addTenantRoleMappingToCognito({
			authenticatedRoleArn: tenantAuthenticatedRoleArn,
			userRoleArn: tenantUserRoleArn,
			adminRoleArn: tenantAdminRoleArn,
			userPoolId,
			identityPoolId,
			clientId,
		});

		return {
			userPoolId,
			clientId,
			identityPoolId,
			tenantAdminRoleArn,
			tenantUserRoleArn,
			tenantAuthenticatedRoleArn,
			tenantId,
		};
	} catch (e) {
		for (const rollback of rollbacks.reverse()) {
			await rollback.apply();
		}

		throw e;
	}
}
