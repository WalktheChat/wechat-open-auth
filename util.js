/**
 * 对返回结果的一层封装，如果遇见微信返回的错误，将返回一个错误
 * 参见：http://mp.weixin.qq.com/wiki/index.php?title=返回码说明
 */
exports.wrapper = function(data) {
    if (data.errcode) {
        const err = new Error(data.errmsg);
        err.name = 'WeChatAPIError';
        err.code = data.errcode;
        throw err;
    }
    return data;
};
