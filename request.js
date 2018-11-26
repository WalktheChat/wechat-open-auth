const request = require('request');
request.post(
    {
        url: 'http://weixin.ximing.ren/test',
        body: { b: 1 },
        json: true
    },
    function(err, res, body) {
        console.log(body);
    }
);
