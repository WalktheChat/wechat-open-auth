class ComponentAccessToken {
    constructor(data) {
        this.component_access_token = data.component_access_token;
        this.expires_at = data.expires_at;
    }
    isValid() {
        return !!this.component_access_token && new Date().getTime() < this.expires_at;
    }
}
module.exports = ComponentAccessToken;
