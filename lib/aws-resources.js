import { CognitoIdentityServiceProvider, CognitoIdentity, IAM } from 'aws-sdk';

export default class AWSResources {
	constructor({ region, accountId }) {
		this.region = region;
		this.accountId = accountId;
	}

	addTenantRoleMappingToCognito({
		userPoolId,
		identityPoolId,
		clientId,
		authenticatedRoleArn,
		userRoleArn,
		adminRoleArn,
	}) {
		return new Promise((resolve, reject) => {
			const cognitoidentity = new CognitoIdentity({
				apiVersion: '2014-06-30',
				region: this.region,
			});

			const params = {
				IdentityPoolId: identityPoolId,
				Roles: {
					authenticated: authenticatedRoleArn,
				},
				RoleMappings: {
					[`cognito-idp.eu-west-1.amazonaws.com/${userPoolId}:${clientId}`]: {
						Type: 'Rules',
						AmbiguousRoleResolution: 'Deny',
						RulesConfiguration: {
							Rules: [
								{
									Claim: 'custom:role',
									MatchType: 'Equals',
									RoleARN: adminRoleArn,
									Value: 'TenantAdmin',
								},
								{
									Claim: 'custom:role',
									MatchType: 'Equals',
									RoleARN: userRoleArn,
									Value: 'TenantUser',
								},
							],
						},
					},
				},
			};

			cognitoidentity.setIdentityPoolRoles(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					const ret = {
						userPoolId,
						identityPoolId,
						clientId,
						authenticatedRoleArn,
						userRoleArn,
						adminRoleArn,
					};

					console.info(
						JSON.stringify({ action: 'setIdentityPoolRoles', ...ret })
					);

					resolve(data);
				}
			});
		});
	}

	addPolicyToRole({ policyArn, roleName }) {
		return new Promise((resolve, reject) => {
			const iam = new IAM({ apiVersion: '2010-05-08' });

			const params = {
				PolicyArn: policyArn,
				RoleName: roleName,
			};

			iam.attachRolePolicy(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					const ret = {
						policyArn,
						roleName,
					};

					console.info(JSON.stringify({ action: 'attachRolePolicy', ...ret }));

					resolve(ret);
				}
			});
		});
	}

	createRole({ name, assumeRolePolicyDocument }) {
		return new Promise((resolve, reject) => {
			const iam = new IAM({ apiVersion: '2010-05-08' });

			var params = {
				AssumeRolePolicyDocument: JSON.stringify(assumeRolePolicyDocument),
				RoleName: name,
			};

			iam.createRole(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					const ret = {
						id: data.Role.RoleId,
						name: data.Role.RoleName,
						arn: data.Role.Arn,
					};

					console.info(JSON.stringify({ action: 'createRole', ...ret }));

					resolve({
						...ret,
						rollback: () =>
							new Promise((resolve, reject) => {
								const params = { RoleName: name };

								console.info(
									JSON.stringify({ action: 'rollbackCreateRole', ...params })
								);

								iam.deleteRole(params, (err, data) =>
									err ? reject(err) : resolve(data)
								);
							}),
					});
				}
			});
		});
	}

	createCognitoUser({
		user: { username, email, firstName, lastName, role },
		userPoolId,
		tenantId,
	}) {
		return new Promise((resolve, reject) => {
			const cognitoidentityserviceprovider = new CognitoIdentityServiceProvider(
				{
					apiVersion: '2016-04-18',
					region: this.region,
				}
			);

			const params = {
				UserPoolId: userPoolId,
				Username: username,
				DesiredDeliveryMediums: ['EMAIL'],
				ForceAliasCreation: true,
				UserAttributes: [
					{
						Name: 'email',
						Value: email,
					},
					{
						Name: 'custom:tenant_id',
						Value: tenantId,
					},
					{
						Name: 'given_name',
						Value: firstName,
					},
					{
						Name: 'family_name',
						Value: lastName,
					},
					{
						Name: 'custom:role',
						Value: role,
					},
				],
			};

			cognitoidentityserviceprovider.adminCreateUser(params, function(
				err,
				_cognitoUser
			) {
				if (err) {
					reject(err);
				} else {
					const ret = {
						username, 
						email, 
						firstName, 
						lastName, 
						role,
						userPoolId,
					};

					console.info(JSON.stringify({ action: 'adminCreateUser', ...ret }));

					resolve({
						...ret,
						rollback: () =>
							new Promise((resolve, reject) => {
								const params = { UserPoolId: userPoolId, Username: username };

								console.info(
									JSON.stringify({
										action: 'rollbackAdminCreateUser',
										...params,
									})
								);

								cognitoidentityserviceprovider.adminDeleteUser(
									params,
									(err, data) => (err ? reject(err) : resolve(data))
								);
							}),
					});
				}
			});
		});
	}

	createPolicy({ name, document, description = '' }) {
		return new Promise((resolve, reject) => {
			const iam = new IAM({ apiVersion: '2010-05-08' });

			const params = {
				PolicyDocument: JSON.stringify(document),
				PolicyName: name,
				Description: description,
			};

			iam.createPolicy(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					const ret = {
						id: data.Policy.PolicyId,
						name: data.Policy.PolicyName,
						arn: data.Policy.Arn,
					};

					console.info(JSON.stringify({ action: 'createPolicy', ...ret }));

					resolve({
						...ret,
						rollback: () =>
							new Promise((resolve, reject) => {
								const params = { PolicyArn: data.Policy.Arn };

								console.info(
									JSON.stringify({ action: 'rollbackCreatePolicy', ...params })
								);

								iam.deletePolicy(params, (err, data) =>
									err ? reject(err) : resolve(data)
								);
							}),
					});
				}
			});
		});
	}

	createIdentityPool({ clientId, userPoolId, name }) {
		return new Promise((resolve, reject) => {
			const cognitoIdentity = new CognitoIdentity({
				apiVersion: '2016-04-18',
				region: this.region,
			});

			const provider = `cognito-idp.eu-west-1.amazonaws.com/${userPoolId}`;

			const params = {
				AllowUnauthenticatedIdentities: false,
				IdentityPoolName: name,
				CognitoIdentityProviders: [
					{
						ClientId: clientId,
						ProviderName: provider,
						ServerSideTokenCheck: true,
					},
				],
			};

			cognitoIdentity.createIdentityPool(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					const ret = { id: data.IdentityPoolId, name: data.IdentityPoolName };

					console.info(
						JSON.stringify({ action: 'createIdentityPool', ...ret })
					);

					resolve({
						...ret,
						rollback: () =>
							new Promise((resolve, reject) => {
								const params = { IdentityPoolId: data.IdentityPoolId };

								console.info(
									JSON.stringify({ action: 'rollbackIdentityPool', ...params })
								);

								cognitoIdentity.deleteIdentityPool(params, (err, data) =>
									err ? reject(err) : resolve(data)
								);
							}),
					});
				}
			});
		});
	}

	createUserPool({ name }) {
		return new Promise((resolve, reject) => {
			const cognitoidentityserviceprovider = new CognitoIdentityServiceProvider(
				{
					apiVersion: '2016-04-18',
					region: this.region,
				}
			);

			const params = {
				PoolName: name,
				AdminCreateUserConfig: {
					AllowAdminCreateUserOnly: true,
					InviteMessageTemplate: {
						EmailMessage: 'Username: {username}<br><br>Password: {####}',
						EmailSubject: 'AWS-SaaS-Identity',
					},
					UnusedAccountValidityDays: 90,
				},
				AliasAttributes: ['phone_number'],
				AutoVerifiedAttributes: ['email'],
				MfaConfiguration: 'OFF',
				Policies: {
					PasswordPolicy: {
						MinimumLength: 8,
						RequireLowercase: true,
						RequireNumbers: true,
						RequireSymbols: false,
						RequireUppercase: true,
					},
				},
				Schema: [
					{
						AttributeDataType: 'String',
						DeveloperOnlyAttribute: false,
						Mutable: false,
						Name: 'tenant_id',
						NumberAttributeConstraints: {
							MaxValue: '256',
							MinValue: '1',
						},
						Required: false,
						StringAttributeConstraints: {
							MaxLength: '256',
							MinLength: '1',
						},
					},
					{
						Name: 'email',
						Required: true,
					},
					{
						AttributeDataType: 'String',
						DeveloperOnlyAttribute: false,
						Mutable: true,
						Name: 'role',
						NumberAttributeConstraints: {
							MaxValue: '256',
							MinValue: '1',
						},
						Required: false,
						StringAttributeConstraints: {
							MaxLength: '256',
							MinLength: '1',
						},
					},
				],
			};

			cognitoidentityserviceprovider.createUserPool(params, function(
				err,
				data
			) {
				if (err) {
					reject(err);
				} else {
					const ret = { id: data.UserPool.Id, name: data.UserPool.Name };

					console.info(JSON.stringify({ action: 'createUserPool', ...ret }));

					resolve({
						...ret,
						rollback: () =>
							new Promise((resolve, reject) => {
								const params = { UserPoolId: data.UserPool.Id };

								console.info(
									JSON.stringify({ action: 'rollbackUserPool', ...params })
								);

								cognitoidentityserviceprovider.deleteUserPool(
									params,
									(err, data) => (err ? reject(err) : resolve(data))
								);
							}),
					});
				}
			});
		});
	}

	createUserPoolClient({ name, userPoolId }) {
		return new Promise((resolve, reject) => {
			const cognitoidentityserviceprovider = new CognitoIdentityServiceProvider(
				{
					apiVersion: '2016-04-18',
					region: this.region,
				}
			);

			const params = {
				ClientName: name,
				UserPoolId: userPoolId,
				GenerateSecret: false,
				ReadAttributes: [
					'email',
					'family_name',
					'given_name',
					'phone_number',
					'preferred_username',
					'custom:tenant_id',
					'custom:role',
				],
				RefreshTokenValidity: 0,
				WriteAttributes: [
					'email',
					'family_name',
					'given_name',
					'phone_number',
					'preferred_username',
					'custom:role',
				],
			};

			cognitoidentityserviceprovider.createUserPoolClient(params, function(
				err,
				data
			) {
				if (err) {
					reject(err);
				} else {
					const ret = {
						id: data.UserPoolClient.ClientId,
						name: data.UserPoolClient.ClientName,
						userPoolId,
					};

					console.info(
						JSON.stringify({ action: 'createUserPoolClient', ...ret })
					);

					resolve({
						...ret,
						rollback: () =>
							new Promise((resolve, reject) => {
								const params = {
									UserPoolId: data.UserPoolClient.UserPoolId,
									ClientId: data.UserPoolClient.ClientId,
								};

								console.info(
									JSON.stringify({
										action: 'rollbackUserPoolClient',
										...params,
									})
								);

								cognitoidentityserviceprovider.deleteUserPoolClient(
									params,
									(err, data) => (err ? reject(err) : resolve(data))
								);
							}),
					});
				}
			});
		});
	}

	getCredentialsForIdentity({ token, identityId, provider }) {
		return new Promise((resolve, reject) => {
			const cognitoidentity = new CognitoIdentity({
				apiVersion: '2014-06-30',
				region: this.region,
			});

			const params = {
				IdentityId: identityId,
				Logins: {
					[provider]: token,
				},
			};

			cognitoidentity.getCredentialsForIdentity(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					resolve(data.Credentials);
				}
			});
		});
	}

	getCognitoIdentityId({ identityPoolId, provider, token }) {
		return new Promise((resolve, reject) => {
			var cognitoidentity = new CognitoIdentity({
				apiVersion: '2014-06-30',
				region: this.region,
			});

			var params = {
				IdentityPoolId: identityPoolId,
				AccountId: this.accountId,
				Logins: {
					[provider]: token,
				},
			};

			cognitoidentity.getId(params, function(err, data) {
				if (err) {
					reject(err);
				} else {
					resolve(data.IdentityId);
				}
			});
		});
	}
}
