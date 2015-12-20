// Twilio service grants that can be attached to an AccessToken
package accesstoken

// Twilio SID resource that can be added to an AccessToken for extra services.
type Grant interface {

	// Convert to JWT payload
	ToPayload() map[string]interface{}

	// Return the JWT paylod key
	key() string
}

// Grant to access Twilio IP Messaging
type IpMessageGrant struct {
	serviceSid string

	endpointId string

	deploymentRoleSid string

	pushCredentialSid string
}

// Grant for Twilio IP Message service
func NewIpMessageGrant(serviceSid, endpointId, deploymentRoleSid, pushCredentialSid string) *IpMessageGrant {

	return &IpMessageGrant{
		serviceSid:        serviceSid,
		endpointId:        endpointId,
		deploymentRoleSid: deploymentRoleSid,
		pushCredentialSid: pushCredentialSid,
	}
}

func (t *IpMessageGrant) ToPayload() map[string]interface{} {

	grant := make(map[string]interface{})

	if len(t.serviceSid) > 0 {
		grant["service_sid"] = t.serviceSid
	}
	if len(t.endpointId) > 0 {
		grant["endpoint_id"] = t.endpointId
	}
	if len(t.deploymentRoleSid) > 0 {
		grant["deployment_role_sid"] = t.deploymentRoleSid
	}
	if len(t.pushCredentialSid) > 0 {
		grant["push_credential_sid"] = t.pushCredentialSid
	}

	return grant
}

func (t *IpMessageGrant) key() string {
	return "ip_messaging"
}

// Grant for Programmable Video access
type ConversationsGrant struct {
	configurationProfileSid string
}

func NewConversationsGrant(sid string) *ConversationsGrant {
	return &ConversationsGrant{configurationProfileSid: sid}
}

func (t *ConversationsGrant) ToPayload() map[string]interface{} {

	if len(t.configurationProfileSid) > 0 {
		return map[string]interface{}{"configuration_profile_sid": t.configurationProfileSid}
	}

	return make(map[string]interface{})
}

func (t *ConversationsGrant) key() string {
	return "rtc"
}
