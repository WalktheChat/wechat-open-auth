const extend = require('util')._extend;
const querystring = require('querystring');
const request = require('request');
const { wrapper } = require('./util');
const ComponentAccessToken = require('./ComponentAccessToken');
const wxcrypto = require('./lib/wxcrypto');
const { parseString } = require('xml2js');

class Auth {
    constructor(
        appid,
        appsecret,
        aesToken,
        aesKey,
        getVerifyTicket,
        saveVerifyTicket,
        getComponentToken,
        saveComponentToken
    ) {
        this.appid = appid;
        this.appsecret = appsecret;
        this.getVerifyTicket = getVerifyTicket;
        this.saveVerifyTicket = saveVerifyTicket;
        this.getComponentToken = getComponentToken || (() => Promise.resolve(this.store));
        this.saveComponentToken =
            saveComponentToken ||
            ((token) => {
                this.store = token;
                if (process.env.NODE_ENV === 'production') {
                    console.warn("Don't save token in memory, when cluster or multi-computer!");
                }
                return token;
            });
        this.prefix = 'https://api.weixin.qq.com/cgi-bin/component/';
        this.snsPrefix = 'https://api.weixin.qq.com/sns/';
        this.newCrypto = new wxcrypto(aesToken, aesKey, this.appid);
    }

    async eventAuth(body) {
        let bodyJson = body;
        if (typeof body === 'string') {
            bodyJson = await new Promise(function(resolve, reject) {
                parseString(body, {}, (err, result) => {
                    if (err) return reject(err);
                    resolve(result);
                });
            });
        }
        console.log('111=>', bodyJson);
        const encryptXml = this.newCrypto.decrypt(bodyJson.xml.Encrypt[0]).message;
        console.log('第三方平台全网发布-----------------------解密后 Xml = ' + encryptXml);
        const encryptJson = await new Promise(function(resolve, reject) {
            parseString(encryptXml, {}, function(err, result) {
                resolve(result);
            });
        });
        console.log(JSON.stringify(encryptJson));
        await this.saveVerifyTicket(encryptJson.xml.ComponentVerifyTicket[0]);
        return encryptJson.xml.ComponentVerifyTicket[0];
    }

    /**
     * 封装weixin请求
     *
     * @param {Object} opts
     */
    request(opts) {
        const options = {};
        let keys = Object.keys(opts);
        for (const key of keys) {
            if (key !== 'headers') {
                options[key] = opts[key];
            } else if (opts.headers) {
                options.headers = options.headers || {};
                extend(options.headers, opts.headers);
            }
        }
        const requestOptions = {
            method: 'POST',
            json: true,
            ...options
        };
        return new Promise((res, rej) => {
            request(requestOptions, (error, response, body) => {
                if (error) rej(error);
                else res(body);
            });
        });
    }

    /*
    * 根据创建auth实例时传入的appid和appsecret获取component_access_token
    * 进行后续所有API调用时，需要先获取这个token
    *
    * 应用开发者不需直接调用本API
    *
    */
    async getComponentAccessToken() {
        const url = `${this.prefix}api_component_token`;
        const verifyTicket = await this.getVerifyTicket();
        const params = {
            component_appid: this.appid,
            component_appsecret: this.appsecret,
            component_verify_ticket: verifyTicket
        };
        const args = {
            url,
            method: 'post',
            body: params
        };
        const token = await this.request(args);
        const expireTime = new Date().getTime() + (token.expires_in - 500) * 1000;
        token.expires_at = expireTime;
        return this.saveComponentToken(token);
    }

    /*!
    * 需要component_access_token的接口调用如果采用preRequest进行封装后，就可以直接调用。
    * 无需依赖getComponentAccessToken为前置调用。
    * 应用开发者无需直接调用此API。
    *
    * Examples:
    * ```
    * auth.preRequest(method, arguments);
    * ```
    * @param {Function} method 需要封装的方法
    * @param {Array} args 方法需要的参数
    */
    async preRequest(method, args, retryed) {
        // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
        const token = await this.getComponentToken();
        // 有token并且token有效直接调用
        if (token && new ComponentAccessToken(token).isValid()) {
            // 暂时保存token
            this.token = token;
            if (!retryed) {
                const data = await method.apply(this, args);
                if (data && data.errcode && data.errcode === 40001) {
                    return this.preRequest(method, args, true);
                }
                return wrapper(data);
            }
            return method.apply(this, args);
        }
        // 从微信获取获取token
        this.token = await this.getComponentAccessToken();
        return method.apply(this, args);
    }

    /*
    * 获取最新的component_access_token
    * 该接口用于开发者调用
    *
    * Examples:
    * ```
    * auth.getLatestComponentToken();
    * ```
    */
    async getLatestComponentToken() {
        // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
        const token = await this.getComponentToken();
        if (token && new ComponentAccessToken(token).isValid()) {
            return token;
        }
        // 使用appid/appsecret获取token
        return this.getComponentAccessToken();
    }

    /*
   * 获取预授权码pre_auth_code
   * 
   * Result:
   * ```
   * {"pre_auth_code": "PRE_AUTH_CODE", "expires_in": 600}
   * ```
   * 开发者需要检查预授权码是否过期
   *
   */
    async getPreAuthCode(...args) {
        const res = await this.preRequest(this._getPreAuthCode, args);
        return res;
    }

    /*!
   * 获取预授权码的未封装版本
   */
    async _getPreAuthCode() {
        const url = `${this.prefix}api_create_preauthcode?component_access_token=${
            this.token.component_access_token
        }`;
        const params = {
            component_appid: this.appid
        };
        const args = {
            url,
            method: 'post',
            body: params,
            json: true
        };
        return wrapper(await this.request(args));
    }

    /*
   * 使用授权码换取公众号的接口调用凭据和授权信息
   * 这个接口需要在用户授权回调URI中调用，拿到用户公众号的调用
   * 凭证并保持下来（缓存or数据库）
   * 仅需在授权的时候调用一次
   *
   * Result:
   * ```
   * {
   *   "authorization_info": {
   *     "authorizer_appid": "wxf8b4f85f3a794e77",
   *     "authorizer_access_token": "AURH_ACCESS_CODE",
   *     "expires_in": 7200,
   *     "authorizer_refresh_token": "AUTH_REFRESH_TOKEN",
   *     "func_info": [
   *     ]
   *   }
   * }
   *
   * @param {String} auth_code 授权码
   */
    getAuthToken(...args) {
        return this.preRequest(this._getAuthToken, args);
    }

    /*!
   * 获取授权信息的未封装版本
   */
    async _getAuthToken(auth_code) {
        const url = `${this.prefix}api_query_auth?component_access_token=${
            this.token.component_access_token
        }`;
        const params = {
            component_appid: this.appid,
            authorization_code: auth_code
        };
        const args = {
            url,
            method: 'post',
            body: params,
            json: true
        };
        return wrapper(await this.request(args));
    }

    /*
   * 获取（刷新）授权公众号的接口调用凭据（Token）
   * 这个接口应该由自动刷新授权授权方令牌的代码调用
   *
   * Result:
   * ```
   * {
   *   "authorizer_access_token": "AURH_ACCESS_CODE",
   *   "expires_in": 7200,
   *   "authorizer_refresh_token": "AUTH_REFRESH_TOKEN",
   * }
   *
   * @param {String} authorizer_appid 授权方appid
   * @param {String} authorizer_refresh_token 授权方的刷新令牌
   */
    refreshAuthToken(...args) {
        return this.preRequest(this._refreshAuthToken, args);
    }

    /*!
   * 未封装的刷新接口调用凭据接口
   */
    async _refreshAuthToken(authorizer_appid, authorizer_refresh_token) {
        const url = `${this.prefix}api_authorizer_token?component_access_token=${
            this.token.component_access_token
        }`;
        const params = {
            component_appid: this.appid,
            authorizer_appid,
            authorizer_refresh_token
        };
        const args = {
            url,
            method: 'post',
            body: params,
            json: true
        };
        return wrapper(await this.request(args));
    }

    /*
   * 获取授权方的公众账号基本信息
   *
   * @param {String} authorizer_appid 授权方appid
   */
    getAuthInfo(...args) {
        return this.preRequest(this._getAuthInfo, args);
    }

    /*!
   * 未封装的获取公众账号基本信息接口
   */
    async _getAuthInfo(authorizer_appid) {
        const url = `${this.prefix}api_get_authorizer_info?component_access_token=${
            this.token.component_access_token
        }`;
        const params = {
            component_appid: this.appid,
            authorizer_appid
        };
        const args = {
            url,
            method: 'post',
            body: params,
            json: true
        };
        return wrapper(await this.request(args));
    }

    /*
   * 获取授权方的选项设置信息
   *
   * @param {String} authorizer_appid 授权方appid
   * @param {String} option_name 选项名称
   */
    getAuthOption(...args) {
        return this.preRequest(this._getAuthOption, args);
    }

    /*!
   * 未封装的获取授权方选项信息
   */
    async _getAuthOption(authorizer_appid, option_name) {
        const url = `${this.prefix}api_get_authorizer_option?component_access_token=${
            this.token.component_access_token
        }`;
        const params = {
            component_appid: this.appid,
            authorizer_appid,
            option_name
        };
        const args = {
            url,
            method: 'post',
            body: params,
            json: true
        };
        return wrapper(await this.request(args));
    }

    /*
   * 设置授权方的选项信息
   *
   * @param {String} authorizer_appid 授权方appid
   * @param {String} option_name 选项名称
   * @param {String} option_value 选项值
   */
    setAuthOption(...args) {
        return this.preRequest(this._setAuthOption, args);
    }

    /*!
   * 未封装的设置授权方选项信息
   */
    async _setAuthOption(authorizer_appid, option_name, option_value) {
        const url = `${this.prefix}api_set_authorizer_option?component_access_token=${
            this.token.component_access_token
        }`;
        const params = {
            component_appid: this.appid,
            authorizer_appid,
            option_name,
            option_value
        };
        const args = {
            url,
            method: 'post',
            body: params,
            json: true
        };
        return wrapper(await this.request(args));
    }

    /** **************** 以下是网页授权相关的接口***************** */

    /**
     * 获取授权页面的URL地址
     * @param {String} appid 授权公众号的appid
     * @param {String} redirect 授权后要跳转的地址
     * @param {String} state 开发者可提供的数据
     * @param {String} scope 作用范围，值为snsapi_userinfo和snsapi_base，前者用于弹出，后者用于跳转
     */
    getOAuthURL(appid, redirect, state, scope) {
        const url = 'https://open.weixin.qq.com/connect/oauth2/authorize';
        const info = {
            appid,
            redirect_uri: redirect,
            response_type: 'code',
            scope: scope || 'snsapi_base',
            state: state || '',
            component_appid: this.appid
        };
        return `${url}?${querystring.stringify(info)}#wechat_redirect`;
    }

    /*
   * 根据授权获取到的code，换取access_token和openid
   *
   * @param {String} appid 授权公众号的appid
   * @param {String} code 授权获取到的code
   */
    getOAuthAccessToken(...args) {
        return this.preRequest(this._getOAuthAccessToken, args);
    }

    /*!
   * 未封装的获取网页授权access_token方法
   */
    async _getOAuthAccessToken(appid, code) {
        const url = `${this.snsPrefix}oauth2/component/access_token`;
        const params = {
            appid,
            code,
            grant_type: 'authorization_code',
            component_appid: this.appid,
            component_access_token: this.token.component_access_token
        };
        const args = {
            method: 'get',
            qs: params,
            json: true,
            url
        };
        return wrapper(await this.request(args));
    }

    /*
   * 刷新网页授权的access_token
   *
   * @param {String} appid 授权公众号的appid
   * @param {String} refresh_token 授权刷新token
   */
    refreshOAuthAccessToken(...args) {
        return this.preRequest(this._refreshOAuthAccessToken, args);
    }

    /*!
   * 未封装的刷新网页授权access_token方法
   */
    async _refreshOAuthAccessToken(appid, refresh_token) {
        const url = `${this.snsPrefix}oauth2/component/refresh_token`;
        const params = {
            appid,
            refresh_token,
            grant_type: 'refresh_token',
            component_appid: this.appid,
            component_access_token: this.token.component_access_token
        };
        const args = {
            method: 'get',
            qs: params,
            json: true,
            url
        };
        return wrapper(await this.request(args));
    }

    /*
   * 通过access_token获取用户基本信息
   *
   * @param {String} openid 授权用户的唯一标识
   * @param {String} access_token 网页授权接口调用凭证
   * @param {String} lang 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
   */
    async getUserInfo(openid, access_token, lang) {
        const url = `${this.snsPrefix}userinfo`;
        const params = {
            openid,
            access_token,
            lang: lang || 'en'
        };
        const args = {
            method: 'get',
            qs: params,
            json: true,
            url
        };
        return wrapper(await this.request(args));
    }
}

module.exports = Auth;
